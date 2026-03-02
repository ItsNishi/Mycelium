//! Persistence mechanism scanning — registry, services, tasks, startup, WMI, COM.

use winreg::enums::*;
use winreg::RegKey;

use mycelium_core::error::Result;
use mycelium_core::types::{PersistenceEntry, PersistenceType};

/// Maximum entries any single scanner may contribute.
const MAX_ENTRIES_PER_SOURCE: usize = 500;

/// Hard cap on the total number of entries returned.
const MAX_TOTAL_ENTRIES: usize = 2000;

/// Collect persistence entries from all Windows subsystems.
///
/// Each scanner catches its own errors internally so that a failure in one
/// subsystem (e.g. WMI unavailable) does not prevent the others from reporting.
pub(crate) fn list_persistence_entries() -> Result<Vec<PersistenceEntry>> {
	let mut entries = Vec::new();

	scan_registry_run(&mut entries);
	scan_startup_folders(&mut entries);
	scan_services(&mut entries);
	scan_scheduled_tasks(&mut entries);
	scan_wmi_subscriptions(&mut entries);
	scan_com_hijacks(&mut entries);

	if entries.len() > MAX_TOTAL_ENTRIES {
		entries.truncate(MAX_TOTAL_ENTRIES);
	}

	Ok(entries)
}

// ---------------------------------------------------------------------------
// Scanner 1 — Registry Run keys
// ---------------------------------------------------------------------------

/// Registry locations that auto-start programs at logon / boot.
const REGISTRY_RUN_PATHS: &[(winreg::HKEY, &str)] = &[
	(
		HKEY_LOCAL_MACHINE,
		r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
	),
	(
		HKEY_LOCAL_MACHINE,
		r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
	),
	(
		HKEY_CURRENT_USER,
		r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
	),
	(
		HKEY_CURRENT_USER,
		r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
	),
	(
		HKEY_LOCAL_MACHINE,
		r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
	),
	(
		HKEY_LOCAL_MACHINE,
		r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
	),
];

fn scan_registry_run(entries: &mut Vec<PersistenceEntry>) {
	let mut count = 0;
	for &(hive, path) in REGISTRY_RUN_PATHS {
		let Ok(key) = RegKey::predef(hive).open_subkey(path) else {
			continue;
		};
		for value_result in key.enum_values() {
			let Ok((name, value)) = value_result else {
				continue;
			};
			entries.push(PersistenceEntry {
				persistence_type: PersistenceType::RegistryRun,
				name,
				location: format!("{}\\{}", hive_name(hive), path),
				value: value.to_string(),
				enabled: true,
				description: None,
			});
			count += 1;
			if count >= MAX_ENTRIES_PER_SOURCE {
				return;
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Scanner 2 — Startup Folders
// ---------------------------------------------------------------------------

fn scan_startup_folders(entries: &mut Vec<PersistenceEntry>) {
	let folders: Vec<(String, &str)> = [
		(
			std::env::var("APPDATA"),
			r"Microsoft\Windows\Start Menu\Programs\Startup",
		),
		(
			std::env::var("PROGRAMDATA"),
			r"Microsoft\Windows\Start Menu\Programs\Startup",
		),
	]
	.into_iter()
	.filter_map(|(root_result, suffix)| {
		let root = root_result.ok()?;
		Some((format!("{root}\\{suffix}"), suffix))
	})
	.collect();

	let mut count = 0;
	for (folder_path, _) in &folders {
		let Ok(dir) = std::fs::read_dir(folder_path) else {
			tracing::debug!("startup folder not readable: {folder_path}");
			continue;
		};
		for entry_result in dir {
			let Ok(entry) = entry_result else { continue };
			let file_name = entry.file_name().to_string_lossy().to_string();
			// Skip the desktop.ini file that Windows puts in every folder.
			if file_name.eq_ignore_ascii_case("desktop.ini") {
				continue;
			}
			let full_path = entry.path().to_string_lossy().to_string();
			entries.push(PersistenceEntry {
				persistence_type: PersistenceType::StartupFolder,
				name: file_name,
				location: folder_path.clone(),
				value: full_path,
				enabled: true,
				description: None,
			});
			count += 1;
			if count >= MAX_ENTRIES_PER_SOURCE {
				return;
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Scanner 3 — Services (non-system Win32 services via registry)
// ---------------------------------------------------------------------------

fn scan_services(entries: &mut Vec<PersistenceEntry>) {
	let Ok(services_key) = RegKey::predef(HKEY_LOCAL_MACHINE)
		.open_subkey(r"SYSTEM\CurrentControlSet\Services")
	else {
		tracing::debug!("failed to open Services registry key");
		return;
	};

	let mut count = 0;
	for name_result in services_key.enum_keys() {
		let Ok(name) = name_result else { continue };
		let Ok(subkey) = services_key.open_subkey(&name) else {
			continue;
		};

		// Only include Win32 services (OwnProcess = 0x10, ShareProcess = 0x20).
		let svc_type: u32 = subkey.get_value("Type").unwrap_or(0);
		if svc_type & 0x30 == 0 {
			continue;
		}

		let image_path: String = subkey.get_value("ImagePath").unwrap_or_default();
		if image_path.is_empty() {
			continue;
		}

		// Skip obviously built-in Windows services.
		if image_path.contains(r"\Windows\") {
			continue;
		}

		let start: u32 = subkey.get_value("Start").unwrap_or(4);
		let enabled = start != 4; // 4 = disabled

		let display_name: Option<String> = subkey.get_value::<String, _>("DisplayName").ok();

		entries.push(PersistenceEntry {
			persistence_type: PersistenceType::Service,
			name: name.clone(),
			location: format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{name}"),
			value: image_path,
			enabled,
			description: display_name,
		});
		count += 1;
		if count >= MAX_ENTRIES_PER_SOURCE {
			return;
		}
	}
}

// ---------------------------------------------------------------------------
// Scanner 4 — Scheduled Tasks (via schtasks.exe CSV output)
// ---------------------------------------------------------------------------

fn scan_scheduled_tasks(entries: &mut Vec<PersistenceEntry>) {
	let Ok(output) = std::process::Command::new("schtasks")
		.args(["/query", "/fo", "CSV", "/v", "/nh"])
		.output()
	else {
		tracing::debug!("failed to run schtasks");
		return;
	};

	if !output.status.success() {
		tracing::debug!(
			"schtasks exited with status {}",
			output.status.code().unwrap_or(-1)
		);
		return;
	}

	let stdout = String::from_utf8_lossy(&output.stdout);
	let mut count = 0;
	for line in stdout.lines() {
		let fields = parse_csv_line(line);
		// CSV columns: HostName(0), TaskName(1), Next Run Time(2), Status(3),
		//              Logon Mode(4), Last Run Time(5), Last Result(6),
		//              Author(7), Task To Run(8), ...
		if fields.len() < 9 {
			continue;
		}

		let task_name = fields[1].trim_matches('"');
		if task_name.contains(r"\Microsoft\") {
			continue;
		}

		let status = fields[3].trim_matches('"');
		let command = fields[8].trim_matches('"');

		entries.push(PersistenceEntry {
			persistence_type: PersistenceType::ScheduledTask,
			name: task_name.to_string(),
			location: "Task Scheduler".to_string(),
			value: command.to_string(),
			enabled: status != "Disabled",
			description: None,
		});
		count += 1;
		if count >= MAX_ENTRIES_PER_SOURCE {
			return;
		}
	}
}

/// Minimal CSV line parser that respects double-quoted fields.
fn parse_csv_line(line: &str) -> Vec<String> {
	let mut fields = Vec::new();
	let mut current = String::new();
	let mut in_quotes = false;
	let mut chars = line.chars().peekable();

	while let Some(ch) = chars.next() {
		match ch {
			'"' if in_quotes => {
				// A doubled quote inside a quoted field is an escaped literal quote.
				if chars.peek() == Some(&'"') {
					current.push('"');
					let _ = chars.next();
				} else {
					in_quotes = false;
				}
			}
			'"' if !in_quotes => {
				in_quotes = true;
			}
			',' if !in_quotes => {
				fields.push(std::mem::take(&mut current));
			}
			_ => {
				current.push(ch);
			}
		}
	}
	fields.push(current);
	fields
}

// ---------------------------------------------------------------------------
// Scanner 5 — WMI Event Subscriptions
// ---------------------------------------------------------------------------

fn scan_wmi_subscriptions(entries: &mut Vec<PersistenceEntry>) {
	let Ok(com_lib) = wmi::COMLibrary::new() else {
		tracing::debug!("failed to initialise COM for WMI subscription scan");
		return;
	};
	let Ok(wmi_con) =
		wmi::WMIConnection::with_namespace_path(r"ROOT\subscription", com_lib)
	else {
		tracing::debug!("failed to connect to ROOT\\subscription namespace");
		return;
	};

	// -- CommandLineEventConsumer --
	#[derive(serde::Deserialize)]
	#[allow(non_snake_case)]
	struct CmdConsumer {
		Name: String,
		CommandLineTemplate: String,
	}

	if let Ok(results) = wmi_con
		.raw_query::<CmdConsumer>("SELECT Name, CommandLineTemplate FROM CommandLineEventConsumer")
	{
		for c in results {
			entries.push(PersistenceEntry {
				persistence_type: PersistenceType::WmiSubscription,
				name: c.Name,
				location: r"ROOT\subscription\CommandLineEventConsumer".to_string(),
				value: c.CommandLineTemplate,
				enabled: true,
				description: None,
			});
		}
	} else {
		tracing::debug!("WMI CommandLineEventConsumer query failed");
	}

	// -- ActiveScriptEventConsumer --
	#[derive(serde::Deserialize)]
	#[allow(non_snake_case)]
	struct ScriptConsumer {
		Name: String,
		ScriptText: String,
	}

	if let Ok(results) = wmi_con
		.raw_query::<ScriptConsumer>("SELECT Name, ScriptText FROM ActiveScriptEventConsumer")
	{
		for c in results {
			entries.push(PersistenceEntry {
				persistence_type: PersistenceType::WmiSubscription,
				name: c.Name,
				location: r"ROOT\subscription\ActiveScriptEventConsumer".to_string(),
				value: c.ScriptText,
				enabled: true,
				description: None,
			});
		}
	} else {
		tracing::debug!("WMI ActiveScriptEventConsumer query failed");
	}
}

// ---------------------------------------------------------------------------
// Scanner 6 — COM Hijacks (HKCU CLSID overrides)
// ---------------------------------------------------------------------------

fn scan_com_hijacks(entries: &mut Vec<PersistenceEntry>) {
	let Ok(clsid_key) = RegKey::predef(HKEY_CURRENT_USER)
		.open_subkey(r"SOFTWARE\Classes\CLSID")
	else {
		tracing::debug!("HKCU\\SOFTWARE\\Classes\\CLSID not accessible");
		return;
	};

	let mut count = 0;
	for clsid_result in clsid_key.enum_keys() {
		let Ok(clsid) = clsid_result else { continue };

		for server_type in &["InprocServer32", "LocalServer32"] {
			let subpath = format!("{clsid}\\{server_type}");
			let Ok(server_key) = clsid_key.open_subkey(&subpath) else {
				continue;
			};
			let value: String = server_key.get_value("").unwrap_or_default();
			if value.is_empty() {
				continue;
			}

			entries.push(PersistenceEntry {
				persistence_type: PersistenceType::ComHijack,
				name: clsid.clone(),
				location: format!(
					r"HKCU\SOFTWARE\Classes\CLSID\{clsid}\{server_type}"
				),
				value,
				enabled: true,
				description: Some(format!("COM {server_type} hijack")),
			});

			count += 1;
			if count >= MAX_ENTRIES_PER_SOURCE {
				return;
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map a predefined hive constant to its conventional short name.
fn hive_name(hive: winreg::HKEY) -> &'static str {
	if hive == HKEY_LOCAL_MACHINE {
		"HKLM"
	} else if hive == HKEY_CURRENT_USER {
		"HKCU"
	} else {
		"UNKNOWN"
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
	use super::*;

	// -- parse_csv_line --

	#[test]
	fn test_csv_simple() {
		let fields = parse_csv_line("a,b,c");
		assert_eq!(fields, vec!["a", "b", "c"]);
	}

	#[test]
	fn test_csv_quoted_fields() {
		let fields = parse_csv_line(r#""hello","world","foo""#);
		assert_eq!(fields, vec!["hello", "world", "foo"]);
	}

	#[test]
	fn test_csv_quoted_comma() {
		let fields = parse_csv_line(r#""a,b",c,"d,e""#);
		assert_eq!(fields, vec!["a,b", "c", "d,e"]);
	}

	#[test]
	fn test_csv_escaped_quote() {
		let fields = parse_csv_line(r#""say ""hello""",b"#);
		assert_eq!(fields, vec![r#"say "hello""#, "b"]);
	}

	#[test]
	fn test_csv_empty_fields() {
		let fields = parse_csv_line(",,,");
		assert_eq!(fields, vec!["", "", "", ""]);
	}

	#[test]
	fn test_csv_single_field() {
		let fields = parse_csv_line("only");
		assert_eq!(fields, vec!["only"]);
	}

	// -- hive_name --

	#[test]
	fn test_hive_name_hklm() {
		assert_eq!(hive_name(HKEY_LOCAL_MACHINE), "HKLM");
	}

	#[test]
	fn test_hive_name_hkcu() {
		assert_eq!(hive_name(HKEY_CURRENT_USER), "HKCU");
	}

	#[test]
	fn test_hive_name_unknown() {
		assert_eq!(hive_name(std::ptr::null_mut()), "UNKNOWN");
	}
}
