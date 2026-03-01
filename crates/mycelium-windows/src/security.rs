//! Security information via WMI and system commands.

use std::process::Command;

use wmi::{COMLibrary, WMIConnection};

use mycelium_core::error::{MyceliumError, Result};
use mycelium_core::types::{
	GroupInfo, KernelModule, ModuleState, SecurityStatus, UserInfo,
};

#[derive(serde::Deserialize)]
#[allow(non_snake_case)]
struct WmiUserAccount {
	Name: Option<String>,
	FullName: Option<String>,
	SID: Option<String>,
	Disabled: Option<bool>,
	LocalAccount: Option<bool>,
}

#[derive(serde::Deserialize)]
#[allow(non_snake_case)]
struct WmiGroup {
	Name: Option<String>,
	SID: Option<String>,
	LocalAccount: Option<bool>,
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

pub fn list_users() -> Result<Vec<UserInfo>> {
	let wmi = new_wmi_connection()?;

	let results: Vec<WmiUserAccount> = wmi
		.raw_query("SELECT Name, FullName, SID, Disabled, LocalAccount FROM Win32_UserAccount WHERE LocalAccount = TRUE")
		.map_err(|e| MyceliumError::OsError {
			code: -1,
			message: format!("WMI user query failed: {e}"),
		})?;

	let users = results
		.into_iter()
		.map(|u| {
			let name = u.Name.unwrap_or_default();
			let home = format!(r"C:\Users\{name}");

			UserInfo {
				name,
				uid: 0,
				gid: 0,
				home,
				shell: "cmd.exe".to_string(),
				groups: Vec::new(),
			}
		})
		.collect();

	Ok(users)
}

pub fn list_groups() -> Result<Vec<GroupInfo>> {
	let wmi = new_wmi_connection()?;

	let results: Vec<WmiGroup> = wmi
		.raw_query("SELECT Name, SID, LocalAccount FROM Win32_Group WHERE LocalAccount = TRUE")
		.map_err(|e| MyceliumError::OsError {
			code: -1,
			message: format!("WMI group query failed: {e}"),
		})?;

	let groups = results
		.into_iter()
		.map(|g| GroupInfo {
			name: g.Name.unwrap_or_default(),
			gid: 0,
			members: Vec::new(),
		})
		.collect();

	Ok(groups)
}

pub fn list_kernel_modules() -> Result<Vec<KernelModule>> {
	// Use driverquery to list loaded drivers (Windows equivalent of kernel modules)
	let output = Command::new("driverquery")
		.args(["/v", "/fo", "csv"])
		.output()
		.map_err(|e| MyceliumError::OsError {
			code: e.raw_os_error().unwrap_or(-1),
			message: format!("failed to run driverquery: {e}"),
		})?;

	if !output.status.success() {
		let stderr = String::from_utf8_lossy(&output.stderr);
		return Err(MyceliumError::OsError {
			code: output.status.code().unwrap_or(-1),
			message: format!("driverquery failed: {stderr}"),
		});
	}

	let stdout = String::from_utf8_lossy(&output.stdout);
	let mut modules = Vec::new();
	let mut first = true;

	for line in stdout.lines() {
		if first {
			first = false;
			continue; // skip header
		}

		let fields: Vec<&str> = parse_csv_line(line);
		if fields.len() < 4 {
			continue;
		}

		let name = fields[0].trim_matches('"').to_string();
		let state_str = fields.get(3).map(|s| s.trim_matches('"')).unwrap_or("");

		let state = if state_str == "Running" {
			ModuleState::Live
		} else {
			ModuleState::Unknown
		};

		modules.push(KernelModule {
			name,
			size_bytes: 0,
			used_by: Vec::new(),
			state,
		});
	}

	Ok(modules)
}

fn parse_csv_line(line: &str) -> Vec<&str> {
	// Simple CSV parser for driverquery output
	let mut fields = Vec::new();
	let mut start = 0;
	let mut in_quotes = false;

	for (i, ch) in line.char_indices() {
		match ch {
			'"' => in_quotes = !in_quotes,
			',' if !in_quotes => {
				fields.push(&line[start..i]);
				start = i + 1;
			}
			_ => {}
		}
	}
	fields.push(&line[start..]);
	fields
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
		Ok(content) => {
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
		Err(_) => false, // OpenSSH not installed
	}
}
