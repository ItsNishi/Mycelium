//! Memory queries via /proc/meminfo and /proc/[pid]/status.

use mycelium_core::error::{MyceliumError, Result};
use mycelium_core::types::{MemoryInfo, ProcessMemory, SwapInfo};
use std::fs;
use std::path::Path;

/// Parse a value in kB from /proc/meminfo.
fn parse_meminfo_kb(content: &str, key: &str) -> u64 {
	content
		.lines()
		.find(|l| l.starts_with(key))
		.and_then(|l| l.split_whitespace().nth(1))
		.and_then(|v| v.parse::<u64>().ok())
		.unwrap_or(0)
}

pub fn memory_info() -> Result<MemoryInfo> {
	let content = fs::read_to_string("/proc/meminfo")?;

	let total = parse_meminfo_kb(&content, "MemTotal:");
	let free = parse_meminfo_kb(&content, "MemFree:");
	let available = parse_meminfo_kb(&content, "MemAvailable:");
	let buffers = parse_meminfo_kb(&content, "Buffers:");
	let cached = parse_meminfo_kb(&content, "Cached:");
	let swap_total = parse_meminfo_kb(&content, "SwapTotal:");
	let swap_free = parse_meminfo_kb(&content, "SwapFree:");

	let total_bytes = total * 1024;
	let free_bytes = free * 1024;
	let available_bytes = available * 1024;
	let used_bytes = total_bytes.saturating_sub(available_bytes);

	Ok(MemoryInfo {
		total_bytes,
		available_bytes,
		used_bytes,
		free_bytes,
		buffers_bytes: buffers * 1024,
		cached_bytes: cached * 1024,
		swap: SwapInfo {
			total_bytes: swap_total * 1024,
			used_bytes: (swap_total - swap_free) * 1024,
			free_bytes: swap_free * 1024,
		},
	})
}

pub fn process_memory(pid: u32) -> Result<ProcessMemory> {
	let status_path = format!("/proc/{pid}/status");
	if !Path::new(&status_path).exists() {
		return Err(MyceliumError::NotFound(format!("process {pid}")));
	}

	let content = fs::read_to_string(&status_path).map_err(|e| {
		if e.kind() == std::io::ErrorKind::PermissionDenied {
			MyceliumError::PermissionDenied(format!("cannot read {status_path}"))
		} else {
			MyceliumError::IoError(e)
		}
	})?;

	let parse_kb = |key: &str| -> u64 {
		content
			.lines()
			.find(|l| l.starts_with(key))
			.and_then(|l| l.split_whitespace().nth(1))
			.and_then(|v| v.parse::<u64>().ok())
			.unwrap_or(0)
			* 1024
	};

	// /proc/[pid]/statm gives us pages, but status gives kB directly
	let rss = parse_kb("VmRSS:");
	let virt = parse_kb("VmSize:");
	let shared = parse_kb("RssFile:") + parse_kb("RssShmem:");
	let text = parse_kb("VmExe:");
	let data = parse_kb("VmData:");

	Ok(ProcessMemory {
		pid,
		rss_bytes: rss,
		virtual_bytes: virt,
		shared_bytes: shared,
		text_bytes: text,
		data_bytes: data,
	})
}
