//! Security information via NetAPI32, WMI, and system commands.

use std::collections::HashMap;
use std::process::Command;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::NetworkManagement::NetManagement::{
	LOCALGROUP_INFO_1, LOCALGROUP_MEMBERS_INFO_3, MAX_PREFERRED_LENGTH,
	NET_USER_ENUM_FILTER_FLAGS, NetApiBufferFree, NetLocalGroupEnum, NetLocalGroupGetMembers,
	NetUserEnum, USER_INFO_3,
};
use wmi::{COMLibrary, WMIConnection};

use mycelium_core::error::{MyceliumError, Result};
use mycelium_core::types::{
	GroupInfo, KernelModule, ModuleState, SecurityStatus, UserInfo,
};

/// Read a null-terminated `PWSTR`, returning an empty string if null.
fn pwstr_to_string(p: PWSTR) -> String {
	if p.is_null() {
		String::new()
	} else {
		unsafe { p.to_string().unwrap_or_default() }
	}
}

/// Encode a Rust string as a null-terminated wide string.
fn to_wide(s: &str) -> Vec<u16> {
	s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Get the members of a local group using `NetLocalGroupGetMembers` (level 3).
fn get_group_members_api(group_name: &str) -> Vec<String> {
	let wide = to_wide(group_name);
	let mut buf: *mut u8 = std::ptr::null_mut();
	let mut entries_read: u32 = 0;
	let mut total_entries: u32 = 0;

	let ret = unsafe {
		NetLocalGroupGetMembers(
			PCWSTR::null(),
			PCWSTR(wide.as_ptr()),
			3,
			&mut buf,
			MAX_PREFERRED_LENGTH,
			&mut entries_read,
			&mut total_entries,
			None,
		)
	};

	if ret != 0 || buf.is_null() {
		return Vec::new();
	}

	let members = unsafe {
		std::slice::from_raw_parts(buf as *const LOCALGROUP_MEMBERS_INFO_3, entries_read as usize)
	};

	let result: Vec<String> = members
		.iter()
		.map(|m| pwstr_to_string(m.lgrmi3_domainandname))
		.filter(|s| !s.is_empty())
		.collect();

	unsafe {
		let _ = NetApiBufferFree(Some(buf as *const _));
	}

	result
}

/// Build a map of username → [group names] by enumerating all local groups and their members.
fn build_user_groups_map() -> HashMap<String, Vec<String>> {
	let mut map: HashMap<String, Vec<String>> = HashMap::new();

	let mut buf: *mut u8 = std::ptr::null_mut();
	let mut entries_read: u32 = 0;
	let mut total_entries: u32 = 0;

	let ret = unsafe {
		NetLocalGroupEnum(
			PCWSTR::null(),
			1,
			&mut buf,
			MAX_PREFERRED_LENGTH,
			&mut entries_read,
			&mut total_entries,
			None,
		)
	};

	if ret != 0 || buf.is_null() {
		return map;
	}

	let groups = unsafe {
		std::slice::from_raw_parts(buf as *const LOCALGROUP_INFO_1, entries_read as usize)
	};

	for group in groups {
		let group_name = pwstr_to_string(group.lgrpi1_name);
		if group_name.is_empty() {
			continue;
		}

		let members = get_group_members_api(&group_name);
		for member in &members {
			// Members may be in DOMAIN\User format — extract just the username
			let username = member.rsplit('\\').next().unwrap_or(member);
			map.entry(username.to_string())
				.or_default()
				.push(group_name.clone());
		}
	}

	unsafe {
		let _ = NetApiBufferFree(Some(buf as *const _));
	}

	map
}

pub fn list_users() -> Result<Vec<UserInfo>> {
	let mut buf: *mut u8 = std::ptr::null_mut();
	let mut entries_read: u32 = 0;
	let mut total_entries: u32 = 0;
	let mut resume_handle: u32 = 0;

	let ret = unsafe {
		NetUserEnum(
			PCWSTR::null(),
			3,
			NET_USER_ENUM_FILTER_FLAGS(2), // FILTER_NORMAL_ACCOUNT
			&mut buf,
			MAX_PREFERRED_LENGTH,
			&mut entries_read,
			&mut total_entries,
			Some(&mut resume_handle),
		)
	};

	if ret != 0 || buf.is_null() {
		return Err(MyceliumError::OsError {
			code: ret as i32,
			message: format!("NetUserEnum failed with code {ret}"),
		});
	}

	let user_infos = unsafe {
		std::slice::from_raw_parts(buf as *const USER_INFO_3, entries_read as usize)
	};

	// Build group membership map
	let groups_map = build_user_groups_map();

	let users = user_infos
		.iter()
		.map(|u| {
			let name = pwstr_to_string(u.usri3_name);
			let home_raw = pwstr_to_string(u.usri3_home_dir);
			let home = if home_raw.is_empty() {
				format!(r"C:\Users\{name}")
			} else {
				home_raw
			};
			let groups = groups_map
				.get(&name)
				.cloned()
				.unwrap_or_default();

			UserInfo {
				name,
				uid: u.usri3_user_id,
				gid: u.usri3_primary_group_id,
				home,
				shell: "cmd.exe".to_string(),
				groups,
			}
		})
		.collect();

	unsafe {
		let _ = NetApiBufferFree(Some(buf as *const _));
	}

	Ok(users)
}

pub fn list_groups() -> Result<Vec<GroupInfo>> {
	let mut buf: *mut u8 = std::ptr::null_mut();
	let mut entries_read: u32 = 0;
	let mut total_entries: u32 = 0;

	let ret = unsafe {
		NetLocalGroupEnum(
			PCWSTR::null(),
			1,
			&mut buf,
			MAX_PREFERRED_LENGTH,
			&mut entries_read,
			&mut total_entries,
			None,
		)
	};

	if ret != 0 || buf.is_null() {
		return Err(MyceliumError::OsError {
			code: ret as i32,
			message: format!("NetLocalGroupEnum failed with code {ret}"),
		});
	}

	let group_infos = unsafe {
		std::slice::from_raw_parts(buf as *const LOCALGROUP_INFO_1, entries_read as usize)
	};

	let groups = group_infos
		.iter()
		.map(|g| {
			let name = pwstr_to_string(g.lgrpi1_name);
			let members = get_group_members_api(&name)
				.into_iter()
				.map(|m| {
					// Normalize DOMAIN\User → User
					m.rsplit('\\')
						.next()
						.unwrap_or(&m)
						.to_string()
				})
				.collect();

			GroupInfo {
				name,
				gid: 0,
				members,
			}
		})
		.collect();

	unsafe {
		let _ = NetApiBufferFree(Some(buf as *const _));
	}

	Ok(groups)
}

#[derive(serde::Deserialize)]
#[allow(non_snake_case)]
struct WmiSystemDriver {
	Name: Option<String>,
	State: Option<String>,
	PathName: Option<String>,
}

/// Expand driver path prefixes like `\SystemRoot\` and `\??\` to real paths.
fn expand_driver_path(path: &str) -> String {
	let win_dir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
	if let Some(rest) = path.strip_prefix(r"\SystemRoot\") {
		format!(r"{win_dir}\{rest}")
	} else if let Some(rest) = path.strip_prefix(r"\??\") {
		rest.to_string()
	} else {
		path.to_string()
	}
}

fn new_wmi_connection() -> Result<WMIConnection> {
	let com = COMLibrary::new().map_err(|e| MyceliumError::OsError {
		code: -1,
		message: format!("COM init failed: {e}"),
	})?;
	WMIConnection::new(com).map_err(|e| MyceliumError::OsError {
		code: -1,
		message: format!("WMI connection failed: {e}"),
	})
}

pub fn list_kernel_modules() -> Result<Vec<KernelModule>> {
	let wmi = new_wmi_connection()?;

	let results: Vec<WmiSystemDriver> = wmi
		.raw_query("SELECT Name, State, PathName FROM Win32_SystemDriver")
		.map_err(|e| MyceliumError::OsError {
			code: -1,
			message: format!("WMI driver query failed: {e}"),
		})?;

	let modules = results
		.into_iter()
		.map(|d| {
			let name = d.Name.unwrap_or_default();
			let state = match d.State.as_deref() {
				Some("Running") => ModuleState::Live,
				_ => ModuleState::Unknown,
			};
			let size_bytes = d
				.PathName
				.as_deref()
				.map(|p| {
					let expanded = expand_driver_path(p);
					std::fs::metadata(&expanded)
						.map(|m| m.len())
						.unwrap_or(0)
				})
				.unwrap_or(0);

			KernelModule {
				name,
				size_bytes,
				used_by: Vec::new(),
				state,
			}
		})
		.collect();

	Ok(modules)
}

pub fn security_status() -> Result<SecurityStatus> {
	// Check if Windows Firewall is active
	let firewall_active = check_firewall_active();

	// Check if Administrator account is enabled
	let admin_enabled = check_admin_enabled();

	// Check if OpenSSH server is installed and has password auth
	let ssh_password_auth = check_ssh_password_auth();

	Ok(SecurityStatus {
		selinux: None,  // Linux-only
		apparmor: None, // Linux-only
		firewall_active,
		root_login_allowed: admin_enabled,
		password_auth_ssh: ssh_password_auth,
	})
}

fn check_firewall_active() -> bool {
	let output = Command::new("netsh")
		.args(["advfirewall", "show", "currentprofile", "state"])
		.output();

	match output {
		Ok(out) => {
			let stdout = String::from_utf8_lossy(&out.stdout);
			stdout.contains("ON")
		}
		Err(_) => false,
	}
}

fn check_admin_enabled() -> bool {
	let output = Command::new("net")
		.args(["user", "Administrator"])
		.output();

	match output {
		Ok(out) => {
			let stdout = String::from_utf8_lossy(&out.stdout);
			// "Account active" line -- "Yes" means enabled
			stdout.lines().any(|line| {
				line.contains("Account active") && line.contains("Yes")
			})
		}
		Err(_) => false,
	}
}

fn check_ssh_password_auth() -> bool {
	// Check if sshd_config exists and has PasswordAuthentication
	let sshd_config = r"C:\ProgramData\ssh\sshd_config";
	match std::fs::read_to_string(sshd_config) {
		Ok(content) => parse_ssh_password_auth(&content),
		Err(_) => false, // OpenSSH not installed
	}
}

/// Parse sshd_config content and return whether password auth is enabled.
fn parse_ssh_password_auth(content: &str) -> bool {
	for line in content.lines() {
		let trimmed = line.trim();
		if trimmed.starts_with('#') {
			continue;
		}
		if trimmed.starts_with("PasswordAuthentication") {
			return trimmed.contains("yes");
		}
	}
	// Default is yes if not explicitly set
	true
}

#[cfg(test)]
mod tests {
	use super::*;

	// -- expand_driver_path --

	#[test]
	fn test_expand_driver_path_system_root() {
		let result = expand_driver_path(r"\SystemRoot\system32\drivers\ntfs.sys");
		// Should replace \SystemRoot\ with the actual system root
		assert!(result.ends_with(r"\system32\drivers\ntfs.sys"));
		assert!(!result.starts_with(r"\SystemRoot"));
	}

	#[test]
	fn test_expand_driver_path_question_prefix() {
		let result = expand_driver_path(r"\??\C:\Windows\system32\drivers\ntfs.sys");
		assert_eq!(result, r"C:\Windows\system32\drivers\ntfs.sys");
	}

	#[test]
	fn test_expand_driver_path_normal() {
		let result = expand_driver_path(r"C:\Windows\system32\drivers\ntfs.sys");
		assert_eq!(result, r"C:\Windows\system32\drivers\ntfs.sys");
	}

	#[test]
	fn test_expand_driver_path_empty() {
		assert_eq!(expand_driver_path(""), "");
	}

	// -- parse_ssh_password_auth --

	#[test]
	fn test_ssh_password_auth_yes() {
		let content = "# Comment\nPasswordAuthentication yes\n";
		assert!(parse_ssh_password_auth(content));
	}

	#[test]
	fn test_ssh_password_auth_no() {
		let content = "PasswordAuthentication no\n";
		assert!(!parse_ssh_password_auth(content));
	}

	#[test]
	fn test_ssh_password_auth_commented_out() {
		// Commented out means default = yes
		let content = "# PasswordAuthentication no\n";
		assert!(parse_ssh_password_auth(content));
	}

	#[test]
	fn test_ssh_password_auth_empty() {
		// Not set means default = yes
		assert!(parse_ssh_password_auth(""));
	}

	#[test]
	fn test_ssh_password_auth_mixed() {
		let content = "# PasswordAuthentication no\nPort 22\nPasswordAuthentication yes\n";
		assert!(parse_ssh_password_auth(content));
	}
}
