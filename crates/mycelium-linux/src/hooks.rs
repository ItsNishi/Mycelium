//! Linux hook detection.
//!
//! Detects LD_PRELOAD library injection, suspicious shared library paths,
//! and ptrace-based process attachment.

use mycelium_core::error::{MyceliumError, Result};
use mycelium_core::types::{HookInfo, HookType};
use std::fs;
use std::path::Path;

/// Standard library directories that are considered safe.
const STANDARD_LIB_DIRS: &[&str] = &[
	"/usr/lib",
	"/usr/lib64",
	"/usr/lib32",
	"/lib",
	"/lib64",
	"/lib32",
	"/usr/local/lib",
	"/usr/local/lib64",
];

/// Detect hooks affecting a process.
pub fn detect_hooks(pid: u32) -> Result<Vec<HookInfo>> {
	if !Path::new(&format!("/proc/{pid}")).exists() {
		return Err(MyceliumError::NotFound(format!("process {pid}")));
	}

	let mut hooks = Vec::new();

	detect_ld_preload(pid, &mut hooks);
	detect_suspicious_libraries(pid, &mut hooks);
	detect_ptrace(pid, &mut hooks);

	Ok(hooks)
}

// ---- LD_PRELOAD detection ----

/// Read /proc/[pid]/environ and check for LD_PRELOAD entries.
fn detect_ld_preload(pid: u32, hooks: &mut Vec<HookInfo>) {
	let env_path = format!("/proc/{pid}/environ");
	let Ok(content) = fs::read(&env_path) else {
		return;
	};

	let text = String::from_utf8_lossy(&content);
	for entry in text.split('\0') {
		if let Some(value) = entry.strip_prefix("LD_PRELOAD=") {
			// LD_PRELOAD can contain multiple colon or space-separated paths
			for lib in value.split([':', ' ']) {
				let lib = lib.trim();
				if lib.is_empty() {
					continue;
				}

				hooks.push(HookInfo {
					hook_type: HookType::LdPreload,
					module: lib.to_string(),
					function: "LD_PRELOAD".to_string(),
					address: 0,
					expected_bytes: Vec::new(),
					actual_bytes: Vec::new(),
					destination: None,
					destination_module: Some(lib.to_string()),
				});
			}
		}
	}
}

/// Parse LD_PRELOAD value into individual library paths.
#[cfg(test)]
fn parse_ld_preload(value: &str) -> Vec<String> {
	value
		.split(|c: char| c == ':' || c == ' ')
		.map(|s| s.trim().to_string())
		.filter(|s| !s.is_empty())
		.collect()
}

// ---- Suspicious library detection ----

/// Check if a library path is outside standard directories.
fn is_suspicious_path(path: &str) -> bool {
	if !path.starts_with('/') {
		return false;
	}
	!STANDARD_LIB_DIRS.iter().any(|dir| path.starts_with(dir))
}

/// Scan /proc/[pid]/maps for .so files loaded from non-standard paths.
fn detect_suspicious_libraries(pid: u32, hooks: &mut Vec<HookInfo>) {
	let maps_path = format!("/proc/{pid}/maps");
	let Ok(content) = fs::read_to_string(&maps_path) else {
		return;
	};

	let mut seen = std::collections::HashSet::new();

	for line in content.lines() {
		// Extract the pathname (last field after inode)
		let path = match extract_maps_pathname(line) {
			Some(p) => p,
			None => continue,
		};

		if !path.contains(".so") {
			continue;
		}

		if !is_suspicious_path(&path) {
			continue;
		}

		// Deduplicate -- same library can appear in multiple regions
		if !seen.insert(path.clone()) {
			continue;
		}

		hooks.push(HookInfo {
			hook_type: HookType::GotPltHook,
			module: path.clone(),
			function: "suspicious library path".to_string(),
			address: 0,
			expected_bytes: Vec::new(),
			actual_bytes: Vec::new(),
			destination: None,
			destination_module: Some(path),
		});
	}
}

/// Extract the pathname field from a /proc/[pid]/maps line.
fn extract_maps_pathname(line: &str) -> Option<String> {
	// Format: address perms offset dev inode pathname
	let mut parts = line.splitn(6, char::is_whitespace);
	let _address = parts.next()?;
	let _perms = parts.next()?;
	let _offset = parts.next()?;
	let _dev = parts.next()?;
	let _inode = parts.next()?;
	parts.next().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

// ---- Ptrace detection ----

/// Check /proc/[pid]/status for TracerPid to detect ptrace attachment.
fn detect_ptrace(pid: u32, hooks: &mut Vec<HookInfo>) {
	let status_path = format!("/proc/{pid}/status");
	let Ok(content) = fs::read_to_string(&status_path) else {
		return;
	};

	let tracer_pid = parse_tracer_pid(&content);
	if tracer_pid == 0 {
		return;
	}

	// Try to get the tracer's process name
	let tracer_name = fs::read_to_string(format!("/proc/{tracer_pid}/comm"))
		.ok()
		.map(|s| s.trim().to_string())
		.unwrap_or_else(|| format!("pid:{tracer_pid}"));

	hooks.push(HookInfo {
		hook_type: HookType::PtraceAttach,
		module: tracer_name.clone(),
		function: format!("ptrace from pid {tracer_pid}"),
		address: 0,
		expected_bytes: Vec::new(),
		actual_bytes: Vec::new(),
		destination: None,
		destination_module: Some(tracer_name),
	});
}

/// Parse TracerPid from /proc/[pid]/status content.
fn parse_tracer_pid(content: &str) -> u32 {
	content
		.lines()
		.find(|l| l.starts_with("TracerPid:"))
		.and_then(|l| l.split_whitespace().nth(1))
		.and_then(|v| v.parse().ok())
		.unwrap_or(0)
}

#[cfg(test)]
mod tests {
	use super::*;

	// parse_ld_preload tests

	#[test]
	fn test_parse_ld_preload_single() {
		let libs = parse_ld_preload("/opt/evil/hook.so");
		assert_eq!(libs, vec!["/opt/evil/hook.so"]);
	}

	#[test]
	fn test_parse_ld_preload_colon_separated() {
		let libs = parse_ld_preload("/opt/a.so:/opt/b.so");
		assert_eq!(libs, vec!["/opt/a.so", "/opt/b.so"]);
	}

	#[test]
	fn test_parse_ld_preload_space_separated() {
		let libs = parse_ld_preload("/opt/a.so /opt/b.so");
		assert_eq!(libs, vec!["/opt/a.so", "/opt/b.so"]);
	}

	#[test]
	fn test_parse_ld_preload_empty() {
		let libs = parse_ld_preload("");
		assert!(libs.is_empty());
	}

	#[test]
	fn test_parse_ld_preload_whitespace_only() {
		let libs = parse_ld_preload("  : : ");
		assert!(libs.is_empty());
	}

	// is_suspicious_path tests

	#[test]
	fn test_is_suspicious_standard_usr_lib() {
		assert!(!is_suspicious_path("/usr/lib/libc.so.6"));
	}

	#[test]
	fn test_is_suspicious_standard_lib64() {
		assert!(!is_suspicious_path("/lib64/ld-linux-x86-64.so.2"));
	}

	#[test]
	fn test_is_suspicious_standard_usr_local_lib() {
		assert!(!is_suspicious_path("/usr/local/lib/libcustom.so"));
	}

	#[test]
	fn test_is_suspicious_opt_path() {
		assert!(is_suspicious_path("/opt/malware/hook.so"));
	}

	#[test]
	fn test_is_suspicious_home_path() {
		assert!(is_suspicious_path("/home/user/.local/lib/evil.so"));
	}

	#[test]
	fn test_is_suspicious_tmp_path() {
		assert!(is_suspicious_path("/tmp/payload.so"));
	}

	#[test]
	fn test_is_suspicious_relative_path() {
		// Relative paths are not suspicious (they don't start with /)
		assert!(!is_suspicious_path("relative.so"));
	}

	// extract_maps_pathname tests

	#[test]
	fn test_extract_maps_pathname_with_file() {
		let line = "7f0e12345000-7f0e12346000 r-xp 00000000 08:01 12345  /usr/lib/libc.so.6";
		assert_eq!(
			extract_maps_pathname(line),
			Some("/usr/lib/libc.so.6".to_string())
		);
	}

	#[test]
	fn test_extract_maps_pathname_anonymous() {
		let line = "7f0e12345000-7f0e12346000 rw-p 00000000 00:00 0";
		assert_eq!(extract_maps_pathname(line), None);
	}

	#[test]
	fn test_extract_maps_pathname_special() {
		let line = "7ffd12345000-7ffd12366000 rw-p 00000000 00:00 0                          [stack]";
		assert_eq!(
			extract_maps_pathname(line),
			Some("[stack]".to_string())
		);
	}

	// parse_tracer_pid tests

	#[test]
	fn test_parse_tracer_pid_none() {
		let content = "Name:\tbash\nTracerPid:\t0\nUid:\t1000\n";
		assert_eq!(parse_tracer_pid(content), 0);
	}

	#[test]
	fn test_parse_tracer_pid_attached() {
		let content = "Name:\ttarget\nTracerPid:\t12345\nUid:\t1000\n";
		assert_eq!(parse_tracer_pid(content), 12345);
	}

	#[test]
	fn test_parse_tracer_pid_missing() {
		let content = "Name:\tbash\nUid:\t1000\n";
		assert_eq!(parse_tracer_pid(content), 0);
	}
}
