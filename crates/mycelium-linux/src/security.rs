//! Security queries: users, groups, kernel modules, LSM status.

use mycelium_core::error::Result;
use mycelium_core::types::*;
use std::fs;

fn parse_passwd_line(line: &str) -> Option<UserInfo> {
	let fields: Vec<&str> = line.split(':').collect();
	if fields.len() < 7 {
		return None;
	}

	Some(UserInfo {
		name: fields[0].to_string(),
		uid: fields[2].parse().unwrap_or(0),
		gid: fields[3].parse().unwrap_or(0),
		home: fields[5].to_string(),
		shell: fields[6].to_string(),
		groups: Vec::new(),
	})
}

pub fn list_users() -> Result<Vec<UserInfo>> {
	let content = fs::read_to_string("/etc/passwd")?;
	let mut users = Vec::new();

	for line in content.lines() {
		if let Some(mut user) = parse_passwd_line(line) {
			user.groups = find_user_groups(&user.name);
			users.push(user);
		}
	}

	Ok(users)
}

fn find_user_groups_in_content(content: &str, username: &str) -> Vec<String> {
	let mut groups = Vec::new();

	for line in content.lines() {
		let fields: Vec<&str> = line.split(':').collect();
		if fields.len() < 4 {
			continue;
		}

		let members: Vec<&str> = fields[3].split(',').collect();
		if members.contains(&username) {
			groups.push(fields[0].to_string());
		}
	}

	groups
}

fn find_user_groups(username: &str) -> Vec<String> {
	let content = fs::read_to_string("/etc/group").unwrap_or_default();
	find_user_groups_in_content(&content, username)
}

fn parse_group_line(line: &str) -> Option<GroupInfo> {
	let fields: Vec<&str> = line.split(':').collect();
	if fields.len() < 4 {
		return None;
	}

	let members: Vec<String> = fields[3]
		.split(',')
		.filter(|s| !s.is_empty())
		.map(|s| s.to_string())
		.collect();

	Some(GroupInfo {
		name: fields[0].to_string(),
		gid: fields[2].parse().unwrap_or(0),
		members,
	})
}

pub fn list_groups() -> Result<Vec<GroupInfo>> {
	let content = fs::read_to_string("/etc/group")?;
	let groups = content.lines().filter_map(parse_group_line).collect();
	Ok(groups)
}

fn parse_module_line(line: &str) -> Option<KernelModule> {
	let fields: Vec<&str> = line.split_whitespace().collect();
	if fields.len() < 3 {
		return None;
	}

	let used_by: Vec<String> = if fields.len() > 3 {
		fields[3]
			.split(',')
			.filter(|s| !s.is_empty() && *s != "-")
			.map(|s| s.to_string())
			.collect()
	} else {
		Vec::new()
	};

	let state = if fields.len() > 4 {
		match fields[4] {
			"Live" => ModuleState::Live,
			"Loading" => ModuleState::Loading,
			"Unloading" => ModuleState::Unloading,
			_ => ModuleState::Unknown,
		}
	} else {
		ModuleState::Unknown
	};

	Some(KernelModule {
		name: fields[0].to_string(),
		size_bytes: fields[1].parse().unwrap_or(0),
		used_by,
		state,
	})
}

pub fn list_kernel_modules() -> Result<Vec<KernelModule>> {
	let content = fs::read_to_string("/proc/modules")?;
	let modules = content.lines().filter_map(parse_module_line).collect();
	Ok(modules)
}

pub fn security_status() -> Result<SecurityStatus> {
	let selinux = check_selinux();
	let apparmor = check_apparmor();

	// Check if firewall is active (nftables or iptables)
	let firewall_active = check_firewall_active();

	// Check SSH config
	let (root_login, password_auth) = check_ssh_config();

	Ok(SecurityStatus {
		selinux,
		apparmor,
		firewall_active,
		root_login_allowed: root_login,
		password_auth_ssh: password_auth,
	})
}

fn check_selinux() -> Option<LsmStatus> {
	let enforce = fs::read_to_string("/sys/fs/selinux/enforce").ok()?;
	let mode = match enforce.trim() {
		"1" => "enforcing",
		"0" => "permissive",
		_ => "unknown",
	};
	Some(LsmStatus {
		enabled: true,
		mode: mode.to_string(),
	})
}

fn check_apparmor() -> Option<LsmStatus> {
	let profiles = fs::read_to_string("/sys/kernel/security/apparmor/profiles").ok()?;
	if profiles.is_empty() {
		return Some(LsmStatus {
			enabled: false,
			mode: "disabled".to_string(),
		});
	}

	// Each line is: "profile_name (mode)"
	// Count profiles by mode to determine dominant state
	let mut enforce_count = 0u32;
	let mut complain_count = 0u32;
	let mut total = 0u32;

	for line in profiles.lines() {
		if line.is_empty() {
			continue;
		}
		total += 1;
		if line.ends_with("(enforce)") {
			enforce_count += 1;
		} else if line.ends_with("(complain)") {
			complain_count += 1;
		}
	}

	let mode = if total == 0 {
		"disabled"
	} else if complain_count > 0 && enforce_count == 0 {
		"complain"
	} else if enforce_count > 0 && complain_count == 0 {
		"enforce"
	} else {
		"mixed"
	};

	Some(LsmStatus {
		enabled: true,
		mode: mode.to_string(),
	})
}

fn check_firewall_active() -> bool {
	// Check nftables
	if let Ok(output) = std::process::Command::new("nft")
		.args(["list", "tables"])
		.output()
		&& output.status.success()
	{
		let stdout = String::from_utf8_lossy(&output.stdout);
		if !stdout.trim().is_empty() {
			return true;
		}
	}

	// Check iptables
	if let Ok(output) = std::process::Command::new("iptables")
		.args(["-L", "-n"])
		.output()
		&& output.status.success()
	{
		let stdout = String::from_utf8_lossy(&output.stdout);
		// Default iptables output with 3 empty built-in chains (INPUT, FORWARD,
		// OUTPUT) produces exactly 2 lines each (header + policy) = 6 lines.
		// Custom chains add 2 more lines each, so count non-empty, non-header
		// lines to detect actual rules rather than relying on a fragile total.
		return stdout.lines().any(|line| {
			let trimmed = line.trim();
			!trimmed.is_empty()
				&& !trimmed.starts_with("Chain ")
				&& !trimmed.starts_with("target")
		});
	}

	false
}

fn parse_ssh_config_content(content: &str) -> (bool, bool) {
	let mut root_login = true; // Default is yes in most distros
	let mut password_auth = true; // Default is yes

	for line in content.lines() {
		let line = line.trim();
		if line.starts_with('#') || line.is_empty() {
			continue;
		}

		let parts: Vec<&str> = line.split_whitespace().collect();
		if parts.len() < 2 {
			continue;
		}

		match parts[0].to_lowercase().as_str() {
			"permitrootlogin" => {
				root_login = matches!(
					parts[1].to_lowercase().as_str(),
					"yes" | "without-password" | "prohibit-password"
				);
			}
			"passwordauthentication" => {
				password_auth = parts[1].to_lowercase() == "yes";
			}
			_ => {}
		}
	}

	(root_login, password_auth)
}

fn check_ssh_config() -> (bool, bool) {
	let content = fs::read_to_string("/etc/ssh/sshd_config").unwrap_or_default();
	parse_ssh_config_content(&content)
}

#[cfg(test)]
mod tests {
	use super::*;

	// parse_passwd_line tests

	#[test]
	fn test_parse_passwd_line_normal() {
		let line = "root:x:0:0:root:/root:/bin/bash";
		let user = parse_passwd_line(line).unwrap();
		assert_eq!(user.name, "root");
		assert_eq!(user.uid, 0);
		assert_eq!(user.gid, 0);
		assert_eq!(user.home, "/root");
		assert_eq!(user.shell, "/bin/bash");
		assert!(user.groups.is_empty());
	}

	#[test]
	fn test_parse_passwd_line_short() {
		assert!(parse_passwd_line("root:x:0").is_none());
	}

	// find_user_groups_in_content tests

	#[test]
	fn test_find_user_groups_found() {
		let content = "wheel:x:10:nishi,root\ndocker:x:998:nishi\nusers:x:100:alice\n";
		let groups = find_user_groups_in_content(content, "nishi");
		assert_eq!(groups, vec!["wheel", "docker"]);
	}

	#[test]
	fn test_find_user_groups_no_members() {
		let content = "wheel:x:10:\nusers:x:100:\n";
		let groups = find_user_groups_in_content(content, "nishi");
		assert!(groups.is_empty());
	}

	// parse_group_line tests

	#[test]
	fn test_parse_group_line_with_members() {
		let group = parse_group_line("wheel:x:10:nishi,root").unwrap();
		assert_eq!(group.name, "wheel");
		assert_eq!(group.gid, 10);
		assert_eq!(group.members, vec!["nishi", "root"]);
	}

	#[test]
	fn test_parse_group_line_no_members() {
		let group = parse_group_line("nogroup:x:65534:").unwrap();
		assert_eq!(group.name, "nogroup");
		assert!(group.members.is_empty());
	}

	// parse_module_line tests

	#[test]
	fn test_parse_module_line_with_deps() {
		let line = "snd_hda_intel 61440 2 snd_hda_codec,snd_pcm Live 0xffffffffa0000000";
		let module = parse_module_line(line).unwrap();
		assert_eq!(module.name, "snd_hda_intel");
		assert_eq!(module.size_bytes, 61440);
		assert_eq!(module.used_by, vec!["snd_hda_codec", "snd_pcm"]);
		assert_eq!(module.state, ModuleState::Live);
	}

	#[test]
	fn test_parse_module_line_dash_dep() {
		let line = "ext4 1024000 1 - Live 0xffffffffa0100000";
		let module = parse_module_line(line).unwrap();
		assert!(module.used_by.is_empty());
	}

	// parse_ssh_config_content tests

	#[test]
	fn test_ssh_config_prohibit_password() {
		let content = "PermitRootLogin prohibit-password\nPasswordAuthentication no\n";
		let (root_login, password_auth) = parse_ssh_config_content(content);
		assert!(root_login);
		assert!(!password_auth);
	}

	#[test]
	fn test_ssh_config_comments_skipped() {
		let content = "\
			#PermitRootLogin no\n\
			PermitRootLogin yes\n\
			# PasswordAuthentication yes\n\
			PasswordAuthentication no\n";
		let (root_login, password_auth) = parse_ssh_config_content(content);
		assert!(root_login);
		assert!(!password_auth);
	}
}
