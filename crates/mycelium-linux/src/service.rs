//! Service and log queries via systemctl and journalctl.
//!
//! Phase 1 uses CLI wrappers. Phase 2 will migrate to D-Bus via zbus.

use mycelium_core::error::{MyceliumError, Result};
use mycelium_core::types::*;
use std::process::Command;

pub fn list_services() -> Result<Vec<ServiceInfo>> {
	let output = Command::new("systemctl")
		.args([
			"list-units",
			"--type=service",
			"--all",
			"--no-pager",
			"--no-legend",
			"--plain",
		])
		.output()
		.map_err(|e| MyceliumError::OsError {
			code: -1,
			message: format!("failed to run systemctl: {e}"),
		})?;

	let stdout = String::from_utf8_lossy(&output.stdout);
	let mut services = Vec::new();

	for line in stdout.lines() {
		let fields: Vec<&str> = line.split_whitespace().collect();
		if fields.len() < 4 {
			continue;
		}

		let unit_name = fields[0]
			.strip_suffix(".service")
			.unwrap_or(fields[0])
			.to_string();

		let state = match fields[3] {
			"running" => ServiceState::Running,
			"exited" | "dead" => ServiceState::Stopped,
			"failed" => ServiceState::Failed,
			"activating" => ServiceState::Activating,
			"deactivating" => ServiceState::Deactivating,
			"reloading" => ServiceState::Reloading,
			_ => ServiceState::Unknown,
		};

		let description = if fields.len() > 4 {
			Some(fields[4..].join(" "))
		} else {
			None
		};

		services.push(ServiceInfo {
			name: unit_name.clone(),
			display_name: unit_name,
			state,
			enabled: fields[1] == "loaded",
			pid: None, // Filled in by service_status for individual queries
			description,
			dependencies: Vec::new(),
		});
	}

	Ok(services)
}

pub fn service_status(name: &str) -> Result<ServiceInfo> {
	let unit = if name.ends_with(".service") {
		name.to_string()
	} else {
		format!("{name}.service")
	};

	let output = Command::new("systemctl")
		.args(["show", &unit, "--no-pager"])
		.output()
		.map_err(|e| MyceliumError::OsError {
			code: -1,
			message: format!("failed to run systemctl show: {e}"),
		})?;

	if !output.status.success() {
		return Err(MyceliumError::NotFound(format!("service {name}")));
	}

	let stdout = String::from_utf8_lossy(&output.stdout);
	let mut info = ServiceInfo {
		name: name.to_string(),
		display_name: name.to_string(),
		state: ServiceState::Unknown,
		enabled: false,
		pid: None,
		description: None,
		dependencies: Vec::new(),
	};

	for line in stdout.lines() {
		if let Some(val) = line.strip_prefix("Description=") {
			info.description = Some(val.to_string());
			info.display_name = val.to_string();
		} else if let Some(val) = line.strip_prefix("ActiveState=") {
			info.state = match val {
				"active" => ServiceState::Running,
				"inactive" | "deactivating" => ServiceState::Stopped,
				"failed" => ServiceState::Failed,
				"activating" => ServiceState::Activating,
				"reloading" => ServiceState::Reloading,
				_ => ServiceState::Unknown,
			};
		} else if let Some(val) = line.strip_prefix("UnitFileState=") {
			info.enabled = val == "enabled";
		} else if let Some(val) = line.strip_prefix("MainPID=") {
			let pid: u32 = val.parse().unwrap_or(0);
			if pid > 0 {
				info.pid = Some(pid);
			}
		} else if let Some(val) = line.strip_prefix("Requires=") {
			info.dependencies = val
				.split_whitespace()
				.filter(|s| !s.is_empty())
				.map(|s| s.strip_suffix(".service").unwrap_or(s).to_string())
				.collect();
		}
	}

	Ok(info)
}

pub fn service_action(name: &str, action: ServiceAction) -> Result<()> {
	let verb = match action {
		ServiceAction::Start => "start",
		ServiceAction::Stop => "stop",
		ServiceAction::Restart => "restart",
		ServiceAction::Reload => "reload",
		ServiceAction::Enable => "enable",
		ServiceAction::Disable => "disable",
	};

	let unit = if name.ends_with(".service") {
		name.to_string()
	} else {
		format!("{name}.service")
	};

	let output = Command::new("systemctl")
		.args([verb, &unit])
		.output()
		.map_err(|e| MyceliumError::OsError {
			code: -1,
			message: format!("failed to run systemctl {verb}: {e}"),
		})?;

	if !output.status.success() {
		let stderr = String::from_utf8_lossy(&output.stderr);
		let stderr = stderr.trim();

		if stderr.contains("Access denied")
			|| stderr.contains("Permission denied")
			|| stderr.contains("authentication required")
			|| stderr.contains("not privileged")
		{
			return Err(MyceliumError::PermissionDenied(format!(
				"cannot {verb} {name} (run as root)"
			)));
		}

		if stderr.contains("not found")
			|| stderr.contains("No such file")
			|| stderr.contains("not loaded")
		{
			return Err(MyceliumError::NotFound(format!("service {name}")));
		}

		return Err(MyceliumError::OsError {
			code: output.status.code().unwrap_or(-1),
			message: format!("systemctl {verb} {name} failed: {stderr}"),
		});
	}

	Ok(())
}

pub fn read_logs(query: &LogQuery) -> Result<Vec<LogEntry>> {
	let mut cmd = Command::new("journalctl");
	cmd.args(["--no-pager", "--output=short-unix"]);

	if let Some(unit) = &query.unit {
		cmd.args(["-u", unit]);
	}

	if let Some(level) = &query.level {
		let priority = match level {
			LogLevel::Emergency => "0",
			LogLevel::Alert => "1",
			LogLevel::Critical => "2",
			LogLevel::Error => "3",
			LogLevel::Warning => "4",
			LogLevel::Notice => "5",
			LogLevel::Info => "6",
			LogLevel::Debug => "7",
		};
		cmd.args(["-p", priority]);
	}

	if let Some(since) = query.since {
		cmd.args(["--since", &format!("@{since}")]);
	}

	if let Some(until) = query.until {
		cmd.args(["--until", &format!("@{until}")]);
	}

	let limit = query.limit.unwrap_or(100);
	cmd.args(["-n", &limit.to_string()]);

	if let Some(grep) = &query.grep {
		const MAX_GREP_LEN: usize = 256;
		if grep.len() > MAX_GREP_LEN {
			return Err(MyceliumError::ParseError(format!(
				"grep pattern too long ({} chars, max {MAX_GREP_LEN})",
				grep.len()
			)));
		}
		cmd.args(["--grep", grep]);
	}

	let output = cmd.output().map_err(|e| MyceliumError::OsError {
		code: -1,
		message: format!("failed to run journalctl: {e}"),
	})?;

	let stdout = String::from_utf8_lossy(&output.stdout);
	let mut entries = Vec::new();

	for line in stdout.lines() {
		if line.is_empty() || line.starts_with("-- ") {
			continue;
		}

		// Format: TIMESTAMP HOSTNAME IDENT[PID]: MESSAGE
		let parts: Vec<&str> = line.splitn(4, ' ').collect();
		if parts.len() < 4 {
			continue;
		}

		let timestamp: u64 = parts[0]
			.parse::<f64>()
			.map(|f| f as u64)
			.unwrap_or(0);

		// parts[1] = hostname, parts[2] = unit/ident, parts[3..] = message
		let unit_raw = parts[2].trim_end_matches(':');
		let (unit_name, pid) = if let Some(bracket_pos) = unit_raw.find('[') {
			let name = &unit_raw[..bracket_pos];
			let pid_str = unit_raw[bracket_pos + 1..]
				.trim_end_matches(']');
			(name.to_string(), pid_str.parse().ok())
		} else {
			(unit_raw.to_string(), None)
		};

		entries.push(LogEntry {
			timestamp,
			level: LogLevel::Info, // journalctl short-unix doesn't include priority
			unit: Some(unit_name),
			message: parts[3].to_string(),
			pid,
			source: Some(parts[1].to_string()),
		});
	}

	Ok(entries)
}
