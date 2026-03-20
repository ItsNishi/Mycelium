//! Service management and log reading via WMI and wevtutil.

use std::mem::size_of;
use std::process::Command;
use std::time::Instant;

use windows::Win32::System::Services::{
	ChangeServiceConfigW, CloseServiceHandle, ControlService, ENUM_SERVICE_TYPE, OpenSCManagerW,
	OpenServiceW, QueryServiceStatusEx, SC_HANDLE, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO,
	SERVICE_AUTO_START, SERVICE_CHANGE_CONFIG, SERVICE_CONTROL_STOP, SERVICE_DISABLED,
	SERVICE_ERROR, SERVICE_NO_CHANGE, SERVICE_QUERY_STATUS, SERVICE_START, SERVICE_STATUS,
	SERVICE_STATUS_PROCESS, SERVICE_STOP, SERVICE_STOPPED, StartServiceW,
};
use windows::core::PCWSTR;
use wmi::{COMLibrary, WMIConnection};

use mycelium_core::error::{MyceliumError, Result};
use mycelium_core::types::{
	LogEntry, LogLevel, LogQuery, ServiceAction, ServiceInfo, ServiceState,
};

/// RAII wrapper for a Windows Service Control Manager handle (`SC_HANDLE`).
/// Automatically calls `CloseServiceHandle` on drop.
struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
	fn drop(&mut self) {
		unsafe {
			let _ = CloseServiceHandle(self.0);
		}
	}
}

impl ScHandle {
	/// Returns the raw `SC_HANDLE`.
	fn raw(&self) -> SC_HANDLE {
		self.0
	}

	/// Returns `true` if the underlying handle is null or invalid.
	#[allow(dead_code)]
	fn is_invalid(&self) -> bool {
		self.0.is_invalid()
	}
}

/// Open a connection to the local Service Control Manager.
fn open_scm() -> Result<ScHandle> {
	let handle = unsafe { OpenSCManagerW(None, None, SC_MANAGER_CONNECT) }.map_err(|e| {
		MyceliumError::OsError {
			code: e.code().0,
			message: format!("OpenSCManagerW failed: {e}"),
		}
	})?;
	Ok(ScHandle(handle))
}

/// Open a named service with the requested access mask.
fn open_service(scm: &ScHandle, name: &str, access: u32) -> Result<ScHandle> {
	let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
	let handle =
		unsafe { OpenServiceW(scm.raw(), PCWSTR(wide.as_ptr()), access) }.map_err(|e| {
			MyceliumError::OsError {
				code: e.code().0,
				message: format!("OpenServiceW({name:?}) failed: {e}"),
			}
		})?;
	Ok(ScHandle(handle))
}

/// Poll `QueryServiceStatusEx` until the service reaches the `SERVICE_STOPPED`
/// state, or until 30 seconds have elapsed.
fn wait_for_stopped(svc: &ScHandle) -> Result<()> {
	let start = Instant::now();
	let mut buf = [0u8; size_of::<SERVICE_STATUS_PROCESS>()];
	let mut needed: u32 = 0;

	loop {
		unsafe {
			QueryServiceStatusEx(
				svc.raw(),
				SC_STATUS_PROCESS_INFO,
				Some(&mut buf),
				&mut needed,
			)
		}
		.map_err(|e| MyceliumError::OsError {
			code: e.code().0,
			message: format!("QueryServiceStatusEx failed: {e}"),
		})?;

		let status = unsafe { &*(buf.as_ptr() as *const SERVICE_STATUS_PROCESS) };
		if status.dwCurrentState == SERVICE_STOPPED {
			return Ok(());
		}
		if start.elapsed().as_secs() > 30 {
			return Err(MyceliumError::Timeout(
				"timed out waiting for service to stop".to_string(),
			));
		}
		let wait_ms = (status.dwWaitHint / 10).clamp(1000, 10000);
		std::thread::sleep(std::time::Duration::from_millis(wait_ms as u64));
	}
}

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
		dependencies: Vec::new(),
	}
}

#[derive(serde::Deserialize)]
#[allow(non_snake_case)]
struct WmiDependentService {
	Antecedent: Option<String>,
	Dependent: Option<String>,
}

/// Extract a service name from a WMI reference string like
/// `\\HOST\root\cimv2:Win32_Service.Name="Foo"`.
fn extract_wmi_name(reference: &str) -> Option<String> {
	let pattern = "Name=\"";
	let start = reference.find(pattern)? + pattern.len();
	let rest = &reference[start..];
	let end = rest.find('"')?;
	Some(rest[..end].to_string())
}

/// Query WMI for service dependencies, returning a map: service_name → Vec<dependency_name>.
fn get_service_dependencies(wmi: &WMIConnection) -> std::collections::HashMap<String, Vec<String>> {
	let mut map: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();

	let results: Vec<WmiDependentService> = wmi
		.raw_query("SELECT Antecedent, Dependent FROM Win32_DependentService")
		.unwrap_or_default();

	for assoc in results {
		if let (Some(ante), Some(dep)) = (assoc.Antecedent, assoc.Dependent)
			&& let Some(dep_name) = extract_wmi_name(&dep)
			&& let Some(ante_name) = extract_wmi_name(&ante)
		{
			map.entry(dep_name).or_default().push(ante_name);
		}
	}

	map
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

	let dep_map = get_service_dependencies(&wmi);
	let mut services: Vec<ServiceInfo> = results.into_iter().map(wmi_to_service_info).collect();
	for svc in &mut services {
		if let Some(deps) = dep_map.get(&svc.name) {
			svc.dependencies = deps.clone();
		}
	}

	Ok(services)
}

pub fn service_status(name: &str) -> Result<ServiceInfo> {
	let wmi = new_wmi_connection()?;

	let query = format!(
		"SELECT Name, DisplayName, State, StartMode, ProcessId, Description \
		 FROM Win32_Service WHERE Name = '{}'",
		name.replace('\'', "''")
	);

	let results: Vec<WmiService> = wmi.raw_query(&query).map_err(|e| MyceliumError::OsError {
		code: -1,
		message: format!("WMI service query failed: {e}"),
	})?;

	let mut info = results
		.into_iter()
		.next()
		.map(wmi_to_service_info)
		.ok_or_else(|| MyceliumError::NotFound(format!("service '{name}'")))?;

	let dep_map = get_service_dependencies(&wmi);
	if let Some(deps) = dep_map.get(&info.name) {
		info.dependencies = deps.clone();
	}

	Ok(info)
}

pub fn service_action(name: &str, action: ServiceAction) -> Result<()> {
	match action {
		ServiceAction::Start => {
			let scm = open_scm()?;
			let svc = open_service(&scm, name, SERVICE_START)?;
			unsafe { StartServiceW(svc.raw(), None) }.map_err(|e| MyceliumError::OsError {
				code: e.code().0,
				message: format!("StartServiceW({name:?}) failed: {e}"),
			})
		}

		ServiceAction::Stop => {
			let scm = open_scm()?;
			let svc = open_service(&scm, name, SERVICE_STOP | SERVICE_QUERY_STATUS)?;
			let mut status = SERVICE_STATUS::default();
			unsafe { ControlService(svc.raw(), SERVICE_CONTROL_STOP, &mut status) }.map_err(|e| {
				MyceliumError::OsError {
					code: e.code().0,
					message: format!("ControlService(STOP, {name:?}) failed: {e}"),
				}
			})
		}

		ServiceAction::Restart => {
			let scm = open_scm()?;
			let svc = open_service(
				&scm,
				name,
				SERVICE_STOP | SERVICE_START | SERVICE_QUERY_STATUS,
			)?;
			// Attempt to stop; ignore the error — service may already be stopped.
			let mut status = SERVICE_STATUS::default();
			let _ = unsafe { ControlService(svc.raw(), SERVICE_CONTROL_STOP, &mut status) };
			wait_for_stopped(&svc)?;
			unsafe { StartServiceW(svc.raw(), None) }.map_err(|e| MyceliumError::OsError {
				code: e.code().0,
				message: format!("StartServiceW({name:?}) failed: {e}"),
			})
		}

		ServiceAction::Reload => Err(MyceliumError::Unsupported(
			"Windows services do not support reload".to_string(),
		)),

		ServiceAction::Enable => {
			let scm = open_scm()?;
			let svc = open_service(&scm, name, SERVICE_CHANGE_CONFIG)?;
			unsafe {
				ChangeServiceConfigW(
					svc.raw(),
					ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
					SERVICE_AUTO_START,
					SERVICE_ERROR(SERVICE_NO_CHANGE),
					PCWSTR::null(),
					PCWSTR::null(),
					None,
					PCWSTR::null(),
					PCWSTR::null(),
					PCWSTR::null(),
					PCWSTR::null(),
				)
			}
			.map_err(|e| MyceliumError::OsError {
				code: e.code().0,
				message: format!("ChangeServiceConfigW(enable, {name:?}) failed: {e}"),
			})
		}

		ServiceAction::Disable => {
			let scm = open_scm()?;
			let svc = open_service(&scm, name, SERVICE_CHANGE_CONFIG)?;
			unsafe {
				ChangeServiceConfigW(
					svc.raw(),
					ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
					SERVICE_DISABLED,
					SERVICE_ERROR(SERVICE_NO_CHANGE),
					PCWSTR::null(),
					PCWSTR::null(),
					None,
					PCWSTR::null(),
					PCWSTR::null(),
					PCWSTR::null(),
					PCWSTR::null(),
				)
			}
			.map_err(|e| MyceliumError::OsError {
				code: e.code().0,
				message: format!("ChangeServiceConfigW(disable, {name:?}) failed: {e}"),
			})
		}
	}
}

pub fn read_logs(query: &LogQuery) -> Result<Vec<LogEntry>> {
	// Use wevtutil to query Windows Event Log
	let log_name = query.unit.as_deref().unwrap_or("System");

	let count = query.limit.unwrap_or(100);

	let args = vec![
		"qe".to_string(),
		log_name.to_string(),
		"/rd:true".to_string(),
		format!("/c:{count}"),
		"/f:text".to_string(),
	];

	let output =
		Command::new("wevtutil")
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
					unit: Some(query.unit.as_deref().unwrap_or("System").to_string()),
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

		if trimmed.starts_with("Log Name:") {
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
		} else if let Some(val) = trimmed.strip_prefix("Date:") {
			current_timestamp = parse_iso8601_timestamp(val.trim());
		} else if let Some(val) = trimmed.strip_prefix("Process ID:") {
			current_pid = val.trim().parse().ok();
		} else if trimmed.starts_with("Description:") {
			if let Some(desc) = trimmed.strip_prefix("Description:") {
				current_message = desc.trim().to_string();
			}
		} else if !trimmed.is_empty()
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
			unit: Some(query.unit.as_deref().unwrap_or("System").to_string()),
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

/// Compute the number of days from Unix epoch (1970-01-01) to a given date.
fn days_from_epoch(year: i64, month: i64, day: i64) -> i64 {
	// Adjust so March is month 0 (simplifies leap-year handling)
	let y = if month <= 2 { year - 1 } else { year };
	let m = if month <= 2 { month + 9 } else { month - 3 };

	// Days in years since epoch
	let era = y / 400;
	let yoe = y - era * 400;
	let doy = (153 * m + 2) / 5 + day - 1;
	let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;

	era * 146097 + doe - 719468
}

/// Parse an ISO 8601 timestamp like `"2024-01-15T10:30:45.1230000Z"` into a Unix timestamp (seconds).
/// Returns 0 on parse failure.
fn parse_iso8601_timestamp(s: &str) -> u64 {
	// Expected: YYYY-MM-DDThh:mm:ss[.frac][Z]
	let s = s.trim();
	if s.len() < 19 {
		return 0;
	}

	let year: i64 = match s[0..4].parse() {
		Ok(v) => v,
		Err(_) => return 0,
	};
	let month: i64 = match s[5..7].parse() {
		Ok(v) => v,
		Err(_) => return 0,
	};
	let day: i64 = match s[8..10].parse() {
		Ok(v) => v,
		Err(_) => return 0,
	};
	let hour: i64 = match s[11..13].parse() {
		Ok(v) => v,
		Err(_) => return 0,
	};
	let minute: i64 = match s[14..16].parse() {
		Ok(v) => v,
		Err(_) => return 0,
	};
	let second: i64 = match s[17..19].parse() {
		Ok(v) => v,
		Err(_) => return 0,
	};

	let days = days_from_epoch(year, month, day);
	let ts = days * 86400 + hour * 3600 + minute * 60 + second;
	if ts < 0 { 0 } else { ts as u64 }
}

fn matches_log_query(entry: &LogEntry, query: &LogQuery) -> bool {
	if let Some(ref level) = query.level
		&& entry.level > *level
	{
		return false;
	}

	if let Some(since) = query.since
		&& entry.timestamp > 0
		&& entry.timestamp < since
	{
		return false;
	}

	if let Some(until) = query.until
		&& entry.timestamp > 0
		&& entry.timestamp > until
	{
		return false;
	}

	if let Some(ref grep) = query.grep
		&& !entry.message.contains(grep.as_str())
	{
		return false;
	}

	true
}

#[cfg(test)]
mod tests {
	use super::*;
	use mycelium_core::types::{LogEntry, LogLevel, LogQuery};

	// -- extract_wmi_name --

	#[test]
	fn test_extract_wmi_name_normal() {
		let reference = r#"\\DESKTOP\root\cimv2:Win32_Service.Name="Spooler""#;
		assert_eq!(extract_wmi_name(reference), Some("Spooler".to_string()));
	}

	#[test]
	fn test_extract_wmi_name_no_name() {
		assert_eq!(extract_wmi_name("no name key here"), None);
	}

	#[test]
	fn test_extract_wmi_name_empty_name() {
		let reference = r#"Name="""#;
		assert_eq!(extract_wmi_name(reference), Some(String::new()));
	}

	#[test]
	fn test_extract_wmi_name_no_closing_quote() {
		assert_eq!(extract_wmi_name(r#"Name="unterminated"#), None);
	}

	// -- parse_iso8601_timestamp --

	#[test]
	fn test_parse_iso8601_normal() {
		// 2024-01-15T10:30:45Z
		let ts = parse_iso8601_timestamp("2024-01-15T10:30:45.0000000Z");
		assert_eq!(ts, 1705314645);
	}

	#[test]
	fn test_parse_iso8601_epoch() {
		let ts = parse_iso8601_timestamp("1970-01-01T00:00:00.0000000Z");
		assert_eq!(ts, 0);
	}

	#[test]
	fn test_parse_iso8601_too_short() {
		assert_eq!(parse_iso8601_timestamp("2024-01"), 0);
	}

	#[test]
	fn test_parse_iso8601_empty() {
		assert_eq!(parse_iso8601_timestamp(""), 0);
	}

	#[test]
	fn test_parse_iso8601_no_fractional() {
		let ts = parse_iso8601_timestamp("2024-01-15T10:30:45Z");
		assert_eq!(ts, 1705314645);
	}

	// -- days_from_epoch --

	#[test]
	fn test_days_from_epoch_unix_epoch() {
		assert_eq!(days_from_epoch(1970, 1, 1), 0);
	}

	#[test]
	fn test_days_from_epoch_known_date() {
		// 2024-01-15 is 19737 days from epoch
		assert_eq!(days_from_epoch(2024, 1, 15), 19737);
	}

	// -- matches_log_query --

	fn make_entry(timestamp: u64, level: LogLevel, message: &str) -> LogEntry {
		LogEntry {
			timestamp,
			level,
			unit: None,
			message: message.to_string(),
			pid: None,
			source: None,
		}
	}

	fn empty_query() -> LogQuery {
		LogQuery {
			unit: None,
			level: None,
			since: None,
			until: None,
			limit: None,
			grep: None,
		}
	}

	#[test]
	fn test_matches_log_query_empty_matches_all() {
		let entry = make_entry(1000, LogLevel::Info, "hello");
		assert!(matches_log_query(&entry, &empty_query()));
	}

	#[test]
	fn test_matches_log_query_since_filters() {
		let entry = make_entry(500, LogLevel::Info, "old");
		let query = LogQuery {
			since: Some(1000),
			..empty_query()
		};
		assert!(!matches_log_query(&entry, &query));
	}

	#[test]
	fn test_matches_log_query_since_passes() {
		let entry = make_entry(1500, LogLevel::Info, "new");
		let query = LogQuery {
			since: Some(1000),
			..empty_query()
		};
		assert!(matches_log_query(&entry, &query));
	}

	#[test]
	fn test_matches_log_query_until_filters() {
		let entry = make_entry(2000, LogLevel::Info, "future");
		let query = LogQuery {
			until: Some(1000),
			..empty_query()
		};
		assert!(!matches_log_query(&entry, &query));
	}

	#[test]
	fn test_matches_log_query_until_passes() {
		let entry = make_entry(500, LogLevel::Info, "past");
		let query = LogQuery {
			until: Some(1000),
			..empty_query()
		};
		assert!(matches_log_query(&entry, &query));
	}

	#[test]
	fn test_matches_log_query_zero_timestamp_not_filtered() {
		// Entries with timestamp 0 (parse failure) should NOT be filtered by since/until
		let entry = make_entry(0, LogLevel::Info, "unknown time");
		let query = LogQuery {
			since: Some(1000),
			until: Some(2000),
			..empty_query()
		};
		assert!(matches_log_query(&entry, &query));
	}

	#[test]
	fn test_matches_log_query_level_filter() {
		let entry = make_entry(1000, LogLevel::Debug, "debug msg");
		let query = LogQuery {
			level: Some(LogLevel::Warning),
			..empty_query()
		};
		assert!(!matches_log_query(&entry, &query));
	}

	#[test]
	fn test_matches_log_query_level_passes() {
		let entry = make_entry(1000, LogLevel::Error, "error msg");
		let query = LogQuery {
			level: Some(LogLevel::Warning),
			..empty_query()
		};
		assert!(matches_log_query(&entry, &query));
	}

	#[test]
	fn test_matches_log_query_grep_matches() {
		let entry = make_entry(1000, LogLevel::Info, "hello world");
		let query = LogQuery {
			grep: Some("world".to_string()),
			..empty_query()
		};
		assert!(matches_log_query(&entry, &query));
	}

	#[test]
	fn test_matches_log_query_grep_no_match() {
		let entry = make_entry(1000, LogLevel::Info, "hello world");
		let query = LogQuery {
			grep: Some("missing".to_string()),
			..empty_query()
		};
		assert!(!matches_log_query(&entry, &query));
	}

	#[test]
	fn test_matches_log_query_combined_since_until() {
		let entry = make_entry(1500, LogLevel::Info, "in range");
		let query = LogQuery {
			since: Some(1000),
			until: Some(2000),
			..empty_query()
		};
		assert!(matches_log_query(&entry, &query));
	}
}
