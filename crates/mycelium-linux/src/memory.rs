//! Memory queries via /proc/meminfo, /proc/[pid]/status, and /proc/[pid]/mem.

use mycelium_core::error::{MyceliumError, Result};
use mycelium_core::types::{MemoryInfo, MemoryRegion, ProcessMemory, SwapInfo};
use std::fs;
use std::io::{Read as _, Seek, SeekFrom, Write as _};
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

/// Parse `/proc/<pid>/maps` into a list of memory regions.
pub fn process_memory_maps(pid: u32) -> Result<Vec<MemoryRegion>> {
	let maps_path = format!("/proc/{pid}/maps");
	if !Path::new(&maps_path).exists() {
		return Err(MyceliumError::NotFound(format!("process {pid}")));
	}

	let content = fs::read_to_string(&maps_path).map_err(|e| match e.kind() {
		std::io::ErrorKind::PermissionDenied => {
			MyceliumError::PermissionDenied(format!("cannot read {maps_path}"))
		}
		_ => MyceliumError::IoError(e),
	})?;

	let mut regions = Vec::new();
	for line in content.lines() {
		let mut parts = line.splitn(6, char::is_whitespace);

		let range = parts.next().unwrap_or("");
		let permissions = parts.next().unwrap_or("").to_string();
		let offset_str = parts.next().unwrap_or("0");
		let device = parts.next().unwrap_or("").to_string();
		let inode_str = parts.next().unwrap_or("0");
		let pathname = parts.next().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());

		let (start_str, end_str) = range.split_once('-').unwrap_or(("0", "0"));
		let start_address = u64::from_str_radix(start_str, 16).unwrap_or(0);
		let end_address = u64::from_str_radix(end_str, 16).unwrap_or(0);
		let offset = u64::from_str_radix(offset_str, 16).unwrap_or(0);
		let inode = inode_str.parse::<u64>().unwrap_or(0);

		regions.push(MemoryRegion {
			start_address,
			end_address,
			permissions,
			offset,
			device,
			inode,
			pathname,
		});
	}

	Ok(regions)
}

/// Maximum bytes allowed per read_process_memory call (1 MiB).
const MAX_READ_SIZE: usize = 1_048_576;

/// Read raw bytes from a process's virtual memory via `/proc/<pid>/mem`.
pub fn read_process_memory(pid: u32, address: u64, size: usize) -> Result<Vec<u8>> {
	if size > MAX_READ_SIZE {
		return Err(MyceliumError::OsError {
			code: 0,
			message: format!(
				"requested read size {size} exceeds maximum {MAX_READ_SIZE} bytes (1 MiB)"
			),
		});
	}

	let mem_path = format!("/proc/{pid}/mem");
	if !Path::new(&format!("/proc/{pid}")).exists() {
		return Err(MyceliumError::NotFound(format!("process {pid}")));
	}

	let mut file = fs::File::open(&mem_path).map_err(|e| match e.kind() {
		std::io::ErrorKind::PermissionDenied => {
			MyceliumError::PermissionDenied(format!("cannot read {mem_path} (requires ptrace or root)"))
		}
		std::io::ErrorKind::NotFound => MyceliumError::NotFound(format!("process {pid}")),
		_ => MyceliumError::IoError(e),
	})?;

	file.seek(SeekFrom::Start(address)).map_err(|e| MyceliumError::OsError {
		code: e.raw_os_error().unwrap_or(0),
		message: format!("failed to seek to address {address:#x}: {e}"),
	})?;

	let mut buf = vec![0u8; size];
	file.read_exact(&mut buf).map_err(|e| {
		let code = e.raw_os_error().unwrap_or(0);
		// EFAULT (14) or EIO (5) typically mean unmapped/inaccessible address
		if code == 14 || code == 5 {
			MyceliumError::OsError {
				code,
				message: format!(
					"address {address:#x} is unmapped or inaccessible in process {pid}"
				),
			}
		} else {
			MyceliumError::OsError {
				code,
				message: format!("failed to read {size} bytes at {address:#x}: {e}"),
			}
		}
	})?;

	Ok(buf)
}

/// Write raw bytes to a process's virtual memory via `/proc/<pid>/mem`.
/// Returns the number of bytes written.
pub fn write_process_memory(pid: u32, address: u64, data: &[u8]) -> Result<usize> {
	let mem_path = format!("/proc/{pid}/mem");
	if !Path::new(&format!("/proc/{pid}")).exists() {
		return Err(MyceliumError::NotFound(format!("process {pid}")));
	}

	let mut file = fs::OpenOptions::new()
		.write(true)
		.open(&mem_path)
		.map_err(|e| match e.kind() {
			std::io::ErrorKind::PermissionDenied => {
				MyceliumError::PermissionDenied(format!(
					"cannot write {mem_path} (requires ptrace or root)"
				))
			}
			std::io::ErrorKind::NotFound => MyceliumError::NotFound(format!("process {pid}")),
			_ => MyceliumError::IoError(e),
		})?;

	file.seek(SeekFrom::Start(address)).map_err(|e| MyceliumError::OsError {
		code: e.raw_os_error().unwrap_or(0),
		message: format!("failed to seek to address {address:#x}: {e}"),
	})?;

	file.write_all(data).map_err(|e| {
		let code = e.raw_os_error().unwrap_or(0);
		if code == 14 || code == 5 {
			MyceliumError::OsError {
				code,
				message: format!(
					"address {address:#x} is unmapped or inaccessible in process {pid}"
				),
			}
		} else {
			MyceliumError::OsError {
				code,
				message: format!("failed to write {} bytes at {address:#x}: {e}", data.len()),
			}
		}
	})?;

	Ok(data.len())
}
