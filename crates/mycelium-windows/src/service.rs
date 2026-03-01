//! Service management and log reading via WMI and wevtutil.

use std::process::Command;

use wmi::{COMLibrary, WMIConnection};

use mycelium_core::error::{MyceliumError, Result};
use mycelium_core::types::{
	LogEntry, LogLevel, LogQuery, ServiceAction, ServiceInfo, ServiceState,
};

#[derive(serde::Deserialize)]
#[allow(non_snake_case)]
struct WmiService {
	Name: Option<String>,
	DisplayName: Option<String>,
	State: Option<String>,
	StartMode: Option<String>,
	ProcessId: Option<u32>,
	Description: Option<String>,
}

fn map_service_state(state: &str) -> ServiceState {
	match state {
		"Running" => ServiceState::Running,
		"Stopped" => ServiceState::Stopped,
		"Start Pending" => ServiceState::Activating,
		"Stop Pending" => ServiceState::Deactivating,
		"Paused" | "Pause Pending" | "Continue Pending" => ServiceState::Unknown,
		_ => ServiceState::Unknown,
	}
}

fn wmi_to_service_info(svc: WmiService) -> ServiceInfo {
	let state = svc
		.State
		.as_deref()
		.map(map_service_state)
		.unwrap_or(ServiceState::Unknown);

	let enabled = svc
		.StartMode
		.as_deref()
		.map(|m| m != "Disabled")
		.unwrap_or(false);

	let pid = svc.ProcessId.filter(|&p| p != 0);

	ServiceInfo {
		name: svc.Name.unwrap_or_default(),
		display_name: svc.DisplayName.unwrap_or_default(),
		state,
		enabled,
		pid,
		description: svc.Description,
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

pub fn list_services() -> Result<Vec<ServiceInfo>> {
	let wmi = new_wmi_connection()?;

	let results: Vec<WmiService> = wmi
		.raw_query(
			"SELECT Name, DisplayName, State, StartMode, ProcessId, Description \
			 FROM Win32_Service",
		)
		.map_err(|e| MyceliumError::OsError {
			code: -1,
			message: format!("WMI service query failed: {e}"),
		})?;

	Ok(results.into_iter().map(wmi_to_service_info).collect())
}

pub fn service_status(name: &str) -> Result<ServiceInfo> {
	let wmi = new_wmi_connection()?;

	let query = format!(
		"SELECT Name, DisplayName, State, StartMode, ProcessId, Description \
		 FROM Win32_Service WHERE Name = '{}'",
		name.replace('\'', "''")
	);

	let results: Vec<WmiService> = wmi.raw_query(&query).map_err(|e| {
		MyceliumError::OsError {
			code: -1,
			message: format!("WMI service query failed: {e}"),
		}
	})?;

	results
		.into_iter()
		.next()
		.map(wmi_to_service_info)
		.ok_or_else(|| MyceliumError::NotFound(format!("service '{name}'")))
}

pub fn service_action(name: &str, action: ServiceAction) -> Result<()> {
	let (cmd, args): (&str, Vec<String>) = match action {
		ServiceAction::Start => ("sc", vec!["start".into(), name.into()]),
		ServiceAction::Stop => ("sc", vec!["stop".into(), name.into()]),
		ServiceAction::Restart => {
			// sc has no restart -- stop then start
			run_sc(&["stop", name])?;
			// Brief pause for service to stop
			std::thread::sleep(std::time::Duration::from_secs(1));
			("sc", vec!["start".into(), name.into()])
		}
		ServiceAction::Reload => {
			return Err(MyceliumError::Unsupported(
				"Windows services do not support reload".to_string(),
			));
		}
		ServiceAction::Enable => (
			"sc",
			vec!["config".into(), name.into(), "start=".into(), "auto".into()],
		),
		ServiceAction::Disable => (
			"sc",
			vec![
				"config".into(),
				name.into(),
				"start=".into(),
				"disabled".into(),
			],
		),
	};

	let args_str: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
	run_sc(&args_str)
}

fn run_sc(args: &[&str]) -> Result<()> {
	let output = Command::new("sc")
		.args(args)
		.output()
		.map_err(|e| MyceliumError::OsError {
			code: e.raw_os_error().unwrap_or(-1),
			message: format!("failed to run sc: {e}"),
		})?;

	if output.status.success() {
		Ok(())
	} else {
		let stderr = String::from_utf8_lossy(&output.stderr);
		let stdout = String::from_utf8_lossy(&output.stdout);
		Err(MyceliumError::OsError {
			code: output.status.code().unwrap_or(-1),
			message: format!("sc failed: {stdout} {stderr}"),
		})
	}
}

pub fn read_logs(query: &LogQuery) -> Result<Vec<LogEntry>> {
	// Use wevtutil to query Windows Event Log
	let log_name = query
		.unit
		.as_deref()
		.unwrap_or("System");

	let count = query.limit.unwrap_or(100);

	let mut args = vec![
		"qe".to_string(),
		log_name.to_string(),
		"/rd:true".to_string(),
		format!("/c:{count}"),
		"/f:text".to_string(),
	];

	let output = Command::new("wevtutil")
		.args(&args)
		.output()
		.map_err(|e| MyceliumError::OsError {
			code: e.raw_os_error().unwrap_or(-1),
			message: format!("failed to run wevtutil: {e}"),
		})?;

	if !output.status.success() {
		let stderr = String::from_utf8_lossy(&output.stderr);
		return Err(MyceliumError::OsError {
			code: output.status.code().unwrap_or(-1),
			message: format!("wevtutil failed: {stderr}"),
		});
	}

	let stdout = String::from_utf8_lossy(&output.stdout);
	let entries = parse_wevtutil_text(&stdout, query);

	Ok(entries)
}

fn parse_wevtutil_text(text: &str, query: &LogQuery) -> Vec<LogEntry> {
	let mut entries = Vec::new();
	let mut current_message = String::new();
	let mut current_level = LogLevel::Info;
	let mut current_source: Option<String> = None;
	let mut current_pid: Option<u32> = None;
	let mut current_timestamp: u64 = 0;

	for line in text.lines() {
		let trimmed = line.trim();

		if trimmed.starts_with("Event[") || trimmed == "---" {
			// Flush previous entry
			if !current_message.is_empty() {
				let entry = LogEntry {
					timestamp: current_timestamp,
					level: current_level,
					unit: Some(
						query.unit.as_deref().unwrap_or("System").to_string(),
					),
					message: current_message.trim().to_string(),
					pid: current_pid,
					source: current_source.take(),
				};

				if matches_log_query(&entry, query) {
					entries.push(entry);
				}

				current_message = String::new();
				current_level = LogLevel::Info;
				current_pid = None;
				current_timestamp = 0;
			}
			continue;
		}

		if let Some(val) = trimmed.strip_prefix("Log Name:") {
			// skip
		} else if let Some(val) = trimmed.strip_prefix("Source:") {
			current_source = Some(val.trim().to_string());
		} else if let Some(val) = trimmed.strip_prefix("Level:") {
			current_level = match val.trim() {
				"Critical" => LogLevel::Critical,
				"Error" => LogLevel::Error,
				"Warning" => LogLevel::Warning,
				"Information" => LogLevel::Info,
				"Verbose" => LogLevel::Debug,
				_ => LogLevel::Info,
			};
		} else if let Some(val) = trimmed.strip_prefix("Process ID:") {
			current_pid = val.trim().parse().ok();
		} else if trimmed.starts_with("Description:") {
			if let Some(desc) = trimmed.strip_prefix("Description:") {
				current_message = desc.trim().to_string();
			}
		} else if !trimmed.is_empty()
			&& !trimmed.starts_with("Date:")
			&& !trimmed.starts_with("Event ID:")
			&& !trimmed.starts_with("Task:")
			&& !trimmed.starts_with("Keywords:")
			&& !trimmed.starts_with("User:")
			&& !trimmed.starts_with("Computer:")
			&& !trimmed.starts_with("OpCode:")
		{
			// Continuation of description
			if !current_message.is_empty() {
				current_message.push(' ');
			}
			current_message.push_str(trimmed);
		}
	}

	// Flush last entry
	if !current_message.is_empty() {
		let entry = LogEntry {
			timestamp: current_timestamp,
			level: current_level,
			unit: Some(
				query.unit.as_deref().unwrap_or("System").to_string(),
			),
			message: current_message.trim().to_string(),
			pid: current_pid,
			source: current_source,
		};
		if matches_log_query(&entry, query) {
			entries.push(entry);
		}
	}

	entries
}

fn matches_log_query(entry: &LogEntry, query: &LogQuery) -> bool {
	if let Some(ref level) = query.level {
		if entry.level > *level {
			return false;
		}
	}

	if let Some(ref grep) = query.grep {
		if !entry.message.contains(grep.as_str()) {
			return false;
		}
	}

	true
}
