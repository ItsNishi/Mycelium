//! Linux persistence mechanism scanning.
//!
//! Scans cron jobs, systemd timers, init scripts, XDG autostart, shell profiles,
//! and udev rules for persistence entries.

use mycelium_core::error::Result;
use mycelium_core::types::{PersistenceEntry, PersistenceType};
use std::fs;
use std::path::Path;

/// Maximum entries per source category.
const MAX_PER_SOURCE: usize = 500;

/// Maximum total entries returned.
const MAX_TOTAL: usize = 2000;

/// Scan all Linux persistence sources and return combined results.
pub fn list_persistence_entries() -> Result<Vec<PersistenceEntry>> {
	let mut entries = Vec::new();

	scan_cron_jobs(&mut entries);
	scan_systemd_timers(&mut entries);
	scan_init_scripts(&mut entries);
	scan_xdg_autostart(&mut entries);
	scan_shell_profiles(&mut entries);
	scan_udev_rules(&mut entries);

	entries.truncate(MAX_TOTAL);
	Ok(entries)
}

// ---- Cron jobs ----

fn scan_cron_jobs(entries: &mut Vec<PersistenceEntry>) {
	let start = entries.len();

	// System crontab
	scan_crontab_file("/etc/crontab", entries);

	// Per-user crontabs
	scan_cron_dir("/var/spool/cron/crontabs", entries);

	// cron.d drop-in directory
	scan_cron_dir("/etc/cron.d", entries);

	// Enforce per-source cap
	entries.truncate(start + MAX_PER_SOURCE);
}

fn scan_crontab_file(path: &str, entries: &mut Vec<PersistenceEntry>) {
	let Ok(content) = fs::read_to_string(path) else {
		return;
	};

	for line in content.lines() {
		let trimmed = line.trim();
		if trimmed.is_empty() || trimmed.starts_with('#') {
			continue;
		}
		// Skip variable assignments (e.g. SHELL=/bin/bash)
		if trimmed.contains('=') && !trimmed.contains(' ') {
			continue;
		}

		entries.push(PersistenceEntry {
			persistence_type: PersistenceType::CronJob,
			name: extract_cron_name(trimmed),
			location: path.to_string(),
			value: trimmed.to_string(),
			enabled: true,
			description: None,
		});
	}
}

fn scan_cron_dir(dir: &str, entries: &mut Vec<PersistenceEntry>) {
	let Ok(read_dir) = fs::read_dir(dir) else {
		return;
	};

	for entry in read_dir.flatten() {
		let path = entry.path();
		if path.is_file() {
			scan_crontab_file(&path.to_string_lossy(), entries);
		}
	}
}

/// Extract a short name from a cron line (last command component).
fn extract_cron_name(line: &str) -> String {
	// Cron lines: "* * * * * command" or "* * * * * user command"
	// Take the last non-schedule field as the command
	let parts: Vec<&str> = line.split_whitespace().collect();
	if parts.len() > 5 {
		// Skip the 5 schedule fields (or 6 if user field present)
		let cmd = parts[5..].join(" ");
		// Return basename of first command word
		cmd.split_whitespace()
			.next()
			.and_then(|c| c.rsplit('/').next())
			.unwrap_or("cron-entry")
			.to_string()
	} else {
		"cron-entry".to_string()
	}
}

// ---- Systemd timers ----

fn scan_systemd_timers(entries: &mut Vec<PersistenceEntry>) {
	let start = entries.len();

	let dirs = [
		"/etc/systemd/system",
		"/usr/lib/systemd/system",
	];

	for dir in &dirs {
		let Ok(read_dir) = fs::read_dir(dir) else {
			continue;
		};

		for entry in read_dir.flatten() {
			let path = entry.path();
			let name = entry.file_name().to_string_lossy().to_string();
			if !name.ends_with(".timer") {
				continue;
			}

			let value = fs::read_to_string(&path).unwrap_or_default();
			let description = extract_unit_description(&value);

			entries.push(PersistenceEntry {
				persistence_type: PersistenceType::SystemdTimer,
				name: name.trim_end_matches(".timer").to_string(),
				location: path.to_string_lossy().to_string(),
				value: extract_timer_schedule(&value),
				enabled: is_systemd_unit_enabled(&path),
				description,
			});
		}
	}

	let max = start + MAX_PER_SOURCE;
	if entries.len() > max {
		entries.truncate(max);
	}
}

/// Extract the Description= from a systemd unit file.
fn extract_unit_description(content: &str) -> Option<String> {
	content
		.lines()
		.find(|l| l.starts_with("Description="))
		.map(|l| l.trim_start_matches("Description=").trim().to_string())
		.filter(|s| !s.is_empty())
}

/// Extract the OnCalendar= or OnBoot= schedule from a timer unit.
fn extract_timer_schedule(content: &str) -> String {
	for line in content.lines() {
		let trimmed = line.trim();
		if trimmed.starts_with("OnCalendar=")
			|| trimmed.starts_with("OnBootSec=")
			|| trimmed.starts_with("OnUnitActiveSec=")
		{
			return trimmed.to_string();
		}
	}
	String::new()
}

/// Check if a systemd unit is enabled by looking for symlinks in .wants directories.
fn is_systemd_unit_enabled(path: &Path) -> bool {
	let name = match path.file_name() {
		Some(n) => n.to_string_lossy().to_string(),
		None => return false,
	};

	let wants_dirs = [
		"/etc/systemd/system/timers.target.wants",
		"/etc/systemd/system/multi-user.target.wants",
	];

	for dir in &wants_dirs {
		let link = format!("{dir}/{name}");
		if Path::new(&link).exists() {
			return true;
		}
	}
	false
}

// ---- Init scripts ----

fn scan_init_scripts(entries: &mut Vec<PersistenceEntry>) {
	let start = entries.len();
	let dir = "/etc/init.d";

	let Ok(read_dir) = fs::read_dir(dir) else {
		return;
	};

	for entry in read_dir.flatten() {
		let path = entry.path();
		if !path.is_file() {
			continue;
		}

		let name = entry.file_name().to_string_lossy().to_string();
		let description = fs::read_to_string(&path)
			.ok()
			.and_then(|c| extract_init_description(&c));

		entries.push(PersistenceEntry {
			persistence_type: PersistenceType::InitScript,
			name,
			location: path.to_string_lossy().to_string(),
			value: String::new(),
			enabled: true,
			description,
		});
	}

	let max = start + MAX_PER_SOURCE;
	if entries.len() > max {
		entries.truncate(max);
	}
}

/// Extract the short description from an init script (### BEGIN INIT INFO block).
fn extract_init_description(content: &str) -> Option<String> {
	let mut in_block = false;
	for line in content.lines() {
		if line.contains("BEGIN INIT INFO") {
			in_block = true;
			continue;
		}
		if line.contains("END INIT INFO") {
			break;
		}
		if in_block
			&& let Some(desc) = line.strip_prefix("# Short-Description:")
		{
			return Some(desc.trim().to_string());
		}
	}
	None
}

// ---- XDG autostart ----

fn scan_xdg_autostart(entries: &mut Vec<PersistenceEntry>) {
	let start = entries.len();

	let mut dirs = vec!["/etc/xdg/autostart".to_string()];

	// User autostart
	if let Ok(home) = std::env::var("HOME") {
		dirs.push(format!("{home}/.config/autostart"));
	}

	for dir in &dirs {
		let Ok(read_dir) = fs::read_dir(dir) else {
			continue;
		};

		for entry in read_dir.flatten() {
			let path = entry.path();
			let name_str = entry.file_name().to_string_lossy().to_string();
			if !name_str.ends_with(".desktop") {
				continue;
			}

			let content = fs::read_to_string(&path).unwrap_or_default();
			let exec = extract_desktop_key(&content, "Exec");
			let display_name = extract_desktop_key(&content, "Name")
				.unwrap_or_else(|| name_str.trim_end_matches(".desktop").to_string());
			let hidden = extract_desktop_key(&content, "Hidden")
				.map(|v| v == "true")
				.unwrap_or(false);

			entries.push(PersistenceEntry {
				persistence_type: PersistenceType::XdgAutostart,
				name: display_name,
				location: path.to_string_lossy().to_string(),
				value: exec.unwrap_or_default(),
				enabled: !hidden,
				description: extract_desktop_key(&content, "Comment"),
			});
		}
	}

	let max = start + MAX_PER_SOURCE;
	if entries.len() > max {
		entries.truncate(max);
	}
}

/// Extract a key=value from a .desktop file (simplified, no group awareness).
fn extract_desktop_key(content: &str, key: &str) -> Option<String> {
	let prefix = format!("{key}=");
	content
		.lines()
		.find(|l| l.starts_with(&prefix))
		.map(|l| l[prefix.len()..].trim().to_string())
		.filter(|s| !s.is_empty())
}

// ---- Shell profiles ----

fn scan_shell_profiles(entries: &mut Vec<PersistenceEntry>) {
	let start = entries.len();

	// System profiles
	if let Ok(read_dir) = fs::read_dir("/etc/profile.d") {
		for entry in read_dir.flatten() {
			let path = entry.path();
			if path.is_file() {
				entries.push(PersistenceEntry {
					persistence_type: PersistenceType::ShellProfile,
					name: entry.file_name().to_string_lossy().to_string(),
					location: path.to_string_lossy().to_string(),
					value: String::new(),
					enabled: true,
					description: Some("system profile drop-in".to_string()),
				});
			}
		}
	}

	// User shell configs
	if let Ok(home) = std::env::var("HOME") {
		let user_files = [
			".bashrc",
			".profile",
			".bash_profile",
			".zshrc",
			".bash_login",
		];

		for file in &user_files {
			let path = format!("{home}/{file}");
			if Path::new(&path).is_file() {
				entries.push(PersistenceEntry {
					persistence_type: PersistenceType::ShellProfile,
					name: file.to_string(),
					location: path,
					value: String::new(),
					enabled: true,
					description: Some("user shell profile".to_string()),
				});
			}
		}
	}

	let max = start + MAX_PER_SOURCE;
	if entries.len() > max {
		entries.truncate(max);
	}
}

// ---- Udev rules ----

fn scan_udev_rules(entries: &mut Vec<PersistenceEntry>) {
	let start = entries.len();
	let dir = "/etc/udev/rules.d";

	let Ok(read_dir) = fs::read_dir(dir) else {
		return;
	};

	for entry in read_dir.flatten() {
		let path = entry.path();
		if !path.is_file() {
			continue;
		}

		let name = entry.file_name().to_string_lossy().to_string();
		entries.push(PersistenceEntry {
			persistence_type: PersistenceType::UdevRule,
			name,
			location: path.to_string_lossy().to_string(),
			value: String::new(),
			enabled: true,
			description: None,
		});
	}

	let max = start + MAX_PER_SOURCE;
	if entries.len() > max {
		entries.truncate(max);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	// extract_cron_name tests

	#[test]
	fn test_extract_cron_name_full_path() {
		assert_eq!(
			extract_cron_name("*/5 * * * * /usr/bin/backup.sh --full"),
			"backup.sh"
		);
	}

	#[test]
	fn test_extract_cron_name_bare_command() {
		assert_eq!(extract_cron_name("0 3 * * * logrotate"), "logrotate");
	}

	#[test]
	fn test_extract_cron_name_short_line() {
		assert_eq!(extract_cron_name("* * * *"), "cron-entry");
	}

	// extract_unit_description tests

	#[test]
	fn test_extract_unit_description_present() {
		let content = "[Unit]\nDescription=Daily cleanup timer\n[Timer]\nOnCalendar=daily\n";
		assert_eq!(
			extract_unit_description(content),
			Some("Daily cleanup timer".to_string())
		);
	}

	#[test]
	fn test_extract_unit_description_missing() {
		let content = "[Unit]\n[Timer]\nOnCalendar=daily\n";
		assert_eq!(extract_unit_description(content), None);
	}

	// extract_timer_schedule tests

	#[test]
	fn test_extract_timer_schedule_calendar() {
		let content = "[Timer]\nOnCalendar=*-*-* 03:00:00\nPersistent=true\n";
		assert_eq!(
			extract_timer_schedule(content),
			"OnCalendar=*-*-* 03:00:00"
		);
	}

	#[test]
	fn test_extract_timer_schedule_boot() {
		let content = "[Timer]\nOnBootSec=5min\n";
		assert_eq!(extract_timer_schedule(content), "OnBootSec=5min");
	}

	#[test]
	fn test_extract_timer_schedule_missing() {
		let content = "[Timer]\nPersistent=true\n";
		assert_eq!(extract_timer_schedule(content), "");
	}

	// extract_init_description tests

	#[test]
	fn test_extract_init_description_present() {
		let content = "#!/bin/sh\n### BEGIN INIT INFO\n# Short-Description: Start the frobnicator\n### END INIT INFO\n";
		assert_eq!(
			extract_init_description(content),
			Some("Start the frobnicator".to_string())
		);
	}

	#[test]
	fn test_extract_init_description_missing() {
		let content = "#!/bin/sh\necho hello\n";
		assert_eq!(extract_init_description(content), None);
	}

	// extract_desktop_key tests

	#[test]
	fn test_extract_desktop_key_exec() {
		let content = "[Desktop Entry]\nName=My App\nExec=/usr/bin/myapp --start\nType=Application\n";
		assert_eq!(
			extract_desktop_key(content, "Exec"),
			Some("/usr/bin/myapp --start".to_string())
		);
	}

	#[test]
	fn test_extract_desktop_key_name() {
		let content = "[Desktop Entry]\nName=My App\nExec=/usr/bin/myapp\n";
		assert_eq!(
			extract_desktop_key(content, "Name"),
			Some("My App".to_string())
		);
	}

	#[test]
	fn test_extract_desktop_key_missing() {
		let content = "[Desktop Entry]\nName=My App\n";
		assert_eq!(extract_desktop_key(content, "Exec"), None);
	}

	#[test]
	fn test_extract_desktop_key_empty_value() {
		let content = "[Desktop Entry]\nExec=\n";
		assert_eq!(extract_desktop_key(content, "Exec"), None);
	}
}
