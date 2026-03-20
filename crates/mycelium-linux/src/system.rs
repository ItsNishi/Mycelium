//! System-level queries via uname, /proc/cpuinfo, /proc/uptime.

use mycelium_core::error::{MyceliumError, Result};
use mycelium_core::types::*;
use std::fs;

fn errno_to_err(e: nix::errno::Errno) -> MyceliumError {
	MyceliumError::OsError {
		code: e as i32,
		message: e.to_string(),
	}
}

pub fn system_info() -> Result<SystemInfo> {
	let uname = nix::sys::utsname::uname().map_err(errno_to_err)?;
	let uptime_secs = uptime()?;

	// Boot time = current time - uptime
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);

	// OS name/version from /etc/os-release
	let (os_name, os_version) = parse_os_release();

	Ok(SystemInfo {
		hostname: uname.nodename().to_string_lossy().to_string(),
		os_name,
		os_version,
		architecture: uname.machine().to_string_lossy().to_string(),
		uptime_seconds: uptime_secs,
		boot_time: now.saturating_sub(uptime_secs),
	})
}

fn parse_os_release_content(content: &str) -> (String, String) {
	let mut name = "Linux".to_string();
	let mut version = String::new();

	for line in content.lines() {
		if let Some(val) = line.strip_prefix("NAME=") {
			name = val.trim_matches('"').to_string();
		} else if let Some(val) = line.strip_prefix("VERSION=") {
			version = val.trim_matches('"').to_string();
		}
	}

	(name, version)
}

fn parse_os_release() -> (String, String) {
	let content = fs::read_to_string("/etc/os-release")
		.or_else(|_| fs::read_to_string("/usr/lib/os-release"))
		.unwrap_or_default();
	parse_os_release_content(&content)
}

pub fn kernel_info() -> Result<KernelInfo> {
	let uname = nix::sys::utsname::uname().map_err(errno_to_err)?;

	let cmdline = fs::read_to_string("/proc/cmdline")
		.unwrap_or_default()
		.trim()
		.to_string();

	Ok(KernelInfo {
		version: uname.version().to_string_lossy().to_string(),
		release: uname.release().to_string_lossy().to_string(),
		architecture: uname.machine().to_string_lossy().to_string(),
		command_line: cmdline,
	})
}

pub fn cpu_info() -> Result<CpuInfo> {
	let content = fs::read_to_string("/proc/cpuinfo")?;

	let mut model_name = String::new();
	let mut frequency_mhz = 0.0;
	let mut cache_size_kb = 0;
	let mut logical_count = 0u32;
	let mut physical_ids = std::collections::HashSet::new();

	for line in content.lines() {
		if let Some(val) = line.strip_prefix("model name\t: ") {
			if model_name.is_empty() {
				model_name = val.to_string();
			}
		} else if let Some(val) = line.strip_prefix("cpu MHz\t\t: ") {
			if frequency_mhz == 0.0 {
				frequency_mhz = val.parse().unwrap_or(0.0);
			}
		} else if let Some(val) = line.strip_prefix("cache size\t: ") {
			if cache_size_kb == 0 {
				cache_size_kb = val.trim_end_matches(" KB").parse().unwrap_or(0);
			}
		} else if line.starts_with("processor\t: ") {
			logical_count += 1;
		} else if let Some(val) = line.strip_prefix("physical id\t: ") {
			physical_ids.insert(val.to_string());
		}
	}

	// cores_per_socket from "cpu cores" field
	let cores_per_socket: u32 = content
		.lines()
		.find(|l| l.starts_with("cpu cores\t: "))
		.and_then(|l| l.strip_prefix("cpu cores\t: "))
		.and_then(|v| v.parse().ok())
		.unwrap_or(1);

	let physical_cores = if physical_ids.is_empty() {
		cores_per_socket
	} else {
		cores_per_socket * physical_ids.len() as u32
	};

	// Load average
	let loadavg = fs::read_to_string("/proc/loadavg").unwrap_or_default();
	let mut load = [0.0f64; 3];
	for (i, val) in loadavg.split_whitespace().take(3).enumerate() {
		load[i] = val.parse().unwrap_or(0.0);
	}

	// CPU usage from /proc/stat (instantaneous snapshot)
	let usage = cpu_usage_snapshot();

	Ok(CpuInfo {
		model_name,
		cores_physical: physical_cores,
		cores_logical: logical_count,
		frequency_mhz,
		cache_size_kb,
		load_average: load,
		usage_percent: usage,
	})
}

fn parse_cpu_usage(content: &str) -> f64 {
	let Some(cpu_line) = content.lines().find(|l| l.starts_with("cpu ")) else {
		return 0.0;
	};

	let fields: Vec<u64> = cpu_line
		.split_whitespace()
		.skip(1)
		.filter_map(|s| s.parse().ok())
		.collect();

	if fields.len() < 4 {
		return 0.0;
	}

	// user + nice + system = busy; idle = fields[3]
	let busy: u64 = fields[0] + fields[1] + fields[2];
	let total: u64 = fields.iter().sum();

	if total == 0 {
		0.0
	} else {
		(busy as f64 / total as f64) * 100.0
	}
}

fn cpu_usage_snapshot() -> f64 {
	let content = fs::read_to_string("/proc/stat").unwrap_or_default();
	parse_cpu_usage(&content)
}

fn parse_uptime_content(content: &str) -> u64 {
	let secs: f64 = content
		.split_whitespace()
		.next()
		.and_then(|s| s.parse().ok())
		.unwrap_or(0.0);
	secs as u64
}

pub fn uptime() -> Result<u64> {
	let content = fs::read_to_string("/proc/uptime")?;
	Ok(parse_uptime_content(&content))
}

#[cfg(test)]
mod tests {
	use super::*;

	// parse_os_release_content tests

	#[test]
	fn test_os_release_quoted() {
		let content = "NAME=\"openSUSE Tumbleweed\"\nVERSION=\"20260301\"\n";
		let (name, version) = parse_os_release_content(content);
		assert_eq!(name, "openSUSE Tumbleweed");
		assert_eq!(version, "20260301");
	}

	#[test]
	fn test_os_release_unquoted() {
		let content = "NAME=Arch\nVERSION=rolling\n";
		let (name, version) = parse_os_release_content(content);
		assert_eq!(name, "Arch");
		assert_eq!(version, "rolling");
	}

	#[test]
	fn test_os_release_missing_version() {
		let content = "NAME=\"Ubuntu\"\nID=ubuntu\n";
		let (name, version) = parse_os_release_content(content);
		assert_eq!(name, "Ubuntu");
		assert_eq!(version, "");
	}

	#[test]
	fn test_os_release_empty() {
		let (name, version) = parse_os_release_content("");
		assert_eq!(name, "Linux");
		assert_eq!(version, "");
	}

	// parse_cpu_usage tests

	#[test]
	fn test_cpu_usage_normal() {
		let content = "cpu  100 50 50 800 0 0 0 0 0 0\ncpu0 50 25 25 400 0 0 0 0 0 0\n";
		let usage = parse_cpu_usage(content);
		// busy = 100+50+50 = 200, total = 1000, usage = 20%
		assert!((usage - 20.0).abs() < 0.01);
	}

	#[test]
	fn test_cpu_usage_all_zeros() {
		let content = "cpu  0 0 0 0 0 0 0 0 0 0\n";
		assert_eq!(parse_cpu_usage(content), 0.0);
	}

	#[test]
	fn test_cpu_usage_no_cpu_line() {
		let content = "intr 12345 0 0 0\n";
		assert_eq!(parse_cpu_usage(content), 0.0);
	}

	// parse_uptime_content tests

	#[test]
	fn test_uptime_normal() {
		assert_eq!(parse_uptime_content("12345.67 45678.90\n"), 12345);
	}

	#[test]
	fn test_uptime_zero() {
		assert_eq!(parse_uptime_content("0.00 0.00\n"), 0);
	}

	#[test]
	fn test_uptime_empty() {
		assert_eq!(parse_uptime_content(""), 0);
	}
}
