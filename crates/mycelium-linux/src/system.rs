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

fn parse_os_release() -> (String, String) {
	let content = fs::read_to_string("/etc/os-release")
		.or_else(|_| fs::read_to_string("/usr/lib/os-release"))
		.unwrap_or_default();

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
				cache_size_kb = val
					.trim_end_matches(" KB")
					.parse()
					.unwrap_or(0);
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

fn cpu_usage_snapshot() -> f64 {
	let content = fs::read_to_string("/proc/stat").unwrap_or_default();
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

pub fn uptime() -> Result<u64> {
	let content = fs::read_to_string("/proc/uptime")?;
	let secs: f64 = content
		.split_whitespace()
		.next()
		.and_then(|s| s.parse().ok())
		.unwrap_or(0.0);
	Ok(secs as u64)
}
