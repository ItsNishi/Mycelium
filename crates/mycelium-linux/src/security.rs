/// Security queries: users, groups, kernel modules, LSM status.

use mycelium_core::error::Result;
use mycelium_core::types::*;
use std::fs;

pub fn list_users() -> Result<Vec<UserInfo>> {
	let content = fs::read_to_string("/etc/passwd")?;
	let mut users = Vec::new();

	for line in content.lines() {
		let fields: Vec<&str> = line.split(':').collect();
		if fields.len() < 7 {
			continue;
		}

		let uid: u32 = fields[2].parse().unwrap_or(0);
		let gid: u32 = fields[3].parse().unwrap_or(0);
		let name = fields[0].to_string();

		// Find supplementary groups
		let groups = find_user_groups(&name);

		users.push(UserInfo {
			name,
			uid,
			gid,
			home: fields[5].to_string(),
			shell: fields[6].to_string(),
			groups,
		});
	}

	Ok(users)
}

fn find_user_groups(username: &str) -> Vec<String> {
	let content = fs::read_to_string("/etc/group").unwrap_or_default();
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

pub fn list_groups() -> Result<Vec<GroupInfo>> {
	let content = fs::read_to_string("/etc/group")?;
	let mut groups = Vec::new();

	for line in content.lines() {
		let fields: Vec<&str> = line.split(':').collect();
		if fields.len() < 4 {
			continue;
		}

		let members: Vec<String> = fields[3]
			.split(',')
			.filter(|s| !s.is_empty())
			.map(|s| s.to_string())
			.collect();

		groups.push(GroupInfo {
			name: fields[0].to_string(),
			gid: fields[2].parse().unwrap_or(0),
			members,
		});
	}

	Ok(groups)
}

pub fn list_kernel_modules() -> Result<Vec<KernelModule>> {
	let content = fs::read_to_string("/proc/modules")?;
	let mut modules = Vec::new();

	for line in content.lines() {
		let fields: Vec<&str> = line.split_whitespace().collect();
		if fields.len() < 3 {
			continue;
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

		modules.push(KernelModule {
			name: fields[0].to_string(),
			size_bytes: fields[1].parse().unwrap_or(0),
			used_by,
			state,
		});
	}

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
	let enabled = !profiles.is_empty();
	Some(LsmStatus {
		enabled,
		mode: if enabled {
			"enforce".to_string()
		} else {
			"disabled".to_string()
		},
	})
}

fn check_firewall_active() -> bool {
	// Check nftables
	if let Ok(output) = std::process::Command::new("nft")
		.args(["list", "tables"])
		.output()
	{
		if output.status.success() {
			let stdout = String::from_utf8_lossy(&output.stdout);
			if !stdout.trim().is_empty() {
				return true;
			}
		}
	}

	// Check iptables
	if let Ok(output) = std::process::Command::new("iptables")
		.args(["-L", "-n"])
		.output()
	{
		if output.status.success() {
			let stdout = String::from_utf8_lossy(&output.stdout);
			// Check if there are any rules beyond default empty chains
			return stdout.lines().count() > 8;
		}
	}

	false
}

fn check_ssh_config() -> (bool, bool) {
	let content = fs::read_to_string("/etc/ssh/sshd_config").unwrap_or_default();
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
				root_login = matches!(parts[1].to_lowercase().as_str(), "yes" | "without-password" | "prohibit-password");
			}
			"passwordauthentication" => {
				password_auth = parts[1].to_lowercase() == "yes";
			}
			_ => {}
		}
	}

	(root_login, password_auth)
}
