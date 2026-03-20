//! Memory queries via /proc/meminfo, /proc/[pid]/status, and /proc/[pid]/mem.

use mycelium_core::error::{MyceliumError, Result};
use mycelium_core::types::{
	MemoryInfo, MemoryMatch, MemoryRegion, MemorySearchOptions, ProcessMemory, SearchPattern,
	SwapInfo,
};
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

/// Parse a single line from `/proc/<pid>/maps` into a memory region.
fn parse_maps_line(line: &str) -> Option<MemoryRegion> {
	let mut parts = line.splitn(6, char::is_whitespace);

	let range = parts.next().filter(|s| !s.is_empty())?;
	let permissions = parts.next().unwrap_or("").to_string();
	let offset_str = parts.next().unwrap_or("0");
	let device = parts.next().unwrap_or("").to_string();
	let inode_str = parts.next().unwrap_or("0");
	let pathname = parts
		.next()
		.map(|s| s.trim().to_string())
		.filter(|s| !s.is_empty());

	let (start_str, end_str) = range.split_once('-')?;
	let start_address = u64::from_str_radix(start_str, 16).unwrap_or(0);
	let end_address = u64::from_str_radix(end_str, 16).unwrap_or(0);
	let offset = u64::from_str_radix(offset_str, 16).unwrap_or(0);
	let inode = inode_str.parse::<u64>().unwrap_or(0);

	Some(MemoryRegion {
		start_address,
		end_address,
		permissions,
		offset,
		device,
		inode,
		pathname,
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

	let regions = content.lines().filter_map(parse_maps_line).collect();
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
		std::io::ErrorKind::PermissionDenied => MyceliumError::PermissionDenied(format!(
			"cannot read {mem_path} (requires ptrace or root)"
		)),
		std::io::ErrorKind::NotFound => MyceliumError::NotFound(format!("process {pid}")),
		_ => MyceliumError::IoError(e),
	})?;

	file.seek(SeekFrom::Start(address))
		.map_err(|e| MyceliumError::OsError {
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

/// Maximum bytes allowed per write_process_memory call (1 MiB).
const MAX_WRITE_SIZE: usize = 1_048_576;

/// Write raw bytes to a process's virtual memory via `/proc/<pid>/mem`.
/// Returns the number of bytes written.
pub fn write_process_memory(pid: u32, address: u64, data: &[u8]) -> Result<usize> {
	if data.len() > MAX_WRITE_SIZE {
		return Err(MyceliumError::OsError {
			code: 0,
			message: format!(
				"requested write size {} exceeds maximum {MAX_WRITE_SIZE} bytes (1 MiB)",
				data.len()
			),
		});
	}

	let mem_path = format!("/proc/{pid}/mem");
	if !Path::new(&format!("/proc/{pid}")).exists() {
		return Err(MyceliumError::NotFound(format!("process {pid}")));
	}

	let mut file = fs::OpenOptions::new()
		.write(true)
		.open(&mem_path)
		.map_err(|e| match e.kind() {
			std::io::ErrorKind::PermissionDenied => MyceliumError::PermissionDenied(format!(
				"cannot write {mem_path} (requires ptrace or root)"
			)),
			std::io::ErrorKind::NotFound => MyceliumError::NotFound(format!("process {pid}")),
			_ => MyceliumError::IoError(e),
		})?;

	file.seek(SeekFrom::Start(address))
		.map_err(|e| MyceliumError::OsError {
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

// ---- Memory search ----

/// Chunk size for reading process memory during search (1 MiB).
const SEARCH_CHUNK_SIZE: usize = 1_048_576;

/// Maximum matches before stopping.
const SEARCH_MAX_MATCHES: usize = 10_000;

/// Maximum context bytes around a match.
const SEARCH_MAX_CONTEXT: usize = 256;

/// Skip regions larger than this (256 MiB).
const SEARCH_MAX_REGION_SIZE: u64 = 256 * 1024 * 1024;

/// Convert a SearchPattern into raw bytes and an optional mask for matching.
///
/// Returns `(needle, mask)`. When `mask` is `None`, use exact byte matching.
/// When `mask` is `Some`, byte `i` matches if `(haystack[i] & mask[i]) == (needle[i] & mask[i])`.
fn pattern_to_bytes(pattern: &SearchPattern) -> (Vec<u8>, Option<Vec<u8>>) {
	match pattern {
		SearchPattern::Bytes(b) => (b.clone(), None),
		SearchPattern::Utf8(s) => (s.as_bytes().to_vec(), None),
		SearchPattern::Utf16(s) => (
			s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect(),
			None,
		),
		SearchPattern::MaskedBytes { pattern, mask } => (pattern.clone(), Some(mask.clone())),
	}
}

/// Find all occurrences of `needle` in `haystack`, returning byte offsets.
///
/// When `mask` is `None`, performs exact matching (fast path).
/// When `mask` is `Some`, byte `i` matches if `(h & m) == (n & m)`.
fn find_all_occurrences(haystack: &[u8], needle: &[u8], mask: Option<&[u8]>) -> Vec<usize> {
	if needle.is_empty() || haystack.len() < needle.len() {
		return Vec::new();
	}

	let mut positions = Vec::new();

	match mask {
		None => {
			// Fast path: exact matching via sliding window
			let mut start = 0;
			while start + needle.len() <= haystack.len() {
				if let Some(pos) = haystack[start..]
					.windows(needle.len())
					.position(|w| w == needle)
				{
					positions.push(start + pos);
					start += pos + 1;
				} else {
					break;
				}
			}
		}
		Some(m) => {
			// Masked matching: per-byte comparison with mask
			let len = needle.len();
			let end = haystack.len() - len;
			for i in 0..=end {
				let mut matched = true;
				for j in 0..len {
					if (haystack[i + j] & m[j]) != (needle[j] & m[j]) {
						matched = false;
						break;
					}
				}
				if matched {
					positions.push(i);
				}
			}
		}
	}

	positions
}

/// Check if a region's permission string matches the required filter.
/// Filter chars like "rw" mean the region must have both 'r' and 'w'.
fn permissions_match(region_perms: &str, filter: &str) -> bool {
	if filter.is_empty() {
		return true;
	}
	for ch in filter.chars() {
		if !region_perms.contains(ch) {
			return false;
		}
	}
	true
}

/// Search process memory for a pattern across all eligible regions.
pub fn search_process_memory(
	pid: u32,
	pattern: &SearchPattern,
	options: &MemorySearchOptions,
) -> Result<Vec<MemoryMatch>> {
	let (needle, mask) = pattern_to_bytes(pattern);
	if needle.is_empty() {
		return Err(MyceliumError::ParseError("search pattern is empty".into()));
	}
	if let Some(ref m) = mask
		&& m.len() != needle.len()
	{
		return Err(MyceliumError::ParseError(
			"mask length must equal pattern length".into(),
		));
	}

	let regions = process_memory_maps(pid)?;
	let max_matches = options.max_matches.min(SEARCH_MAX_MATCHES);
	let context_size = options.context_size.min(SEARCH_MAX_CONTEXT);

	let mem_path = format!("/proc/{pid}/mem");
	let mut file = fs::File::open(&mem_path).map_err(|e| match e.kind() {
		std::io::ErrorKind::PermissionDenied => MyceliumError::PermissionDenied(format!(
			"cannot read {mem_path} (requires ptrace or root)"
		)),
		std::io::ErrorKind::NotFound => MyceliumError::NotFound(format!("process {pid}")),
		_ => MyceliumError::IoError(e),
	})?;

	let mut matches = Vec::new();

	for region in &regions {
		if matches.len() >= max_matches {
			break;
		}

		// Skip non-readable regions
		if !region.permissions.contains('r') {
			continue;
		}

		// Apply permission filter
		if !permissions_match(&region.permissions, &options.permissions_filter) {
			continue;
		}

		// Skip special regions and oversized regions
		let region_size = region.end_address.saturating_sub(region.start_address);
		if region_size == 0 || region_size > SEARCH_MAX_REGION_SIZE {
			continue;
		}

		// Skip pseudo-regions
		if let Some(ref name) = region.pathname
			&& (name.starts_with("[vvar]") || name.starts_with("[vsyscall]"))
		{
			continue;
		}

		// Read in chunks with overlap
		let overlap = needle.len().saturating_sub(1);
		let mut offset = region.start_address;

		while offset < region.end_address && matches.len() < max_matches {
			let remaining = (region.end_address - offset) as usize;
			let read_size = remaining.min(SEARCH_CHUNK_SIZE);

			if file.seek(SeekFrom::Start(offset)).is_err() {
				break;
			}

			let mut buf = vec![0u8; read_size];
			match file.read(&mut buf) {
				Ok(0) => break,
				Ok(n) => buf.truncate(n),
				Err(_) => break,
			}

			for pos in find_all_occurrences(&buf, &needle, mask.as_deref()) {
				if matches.len() >= max_matches {
					break;
				}

				let match_address = offset + pos as u64;

				// Extract context bytes around the match
				let ctx_start = pos.saturating_sub(context_size);
				let ctx_end = (pos + needle.len() + context_size).min(buf.len());
				let context_bytes = buf[ctx_start..ctx_end].to_vec();

				matches.push(MemoryMatch {
					address: match_address,
					region_start: region.start_address,
					region_permissions: region.permissions.clone(),
					region_pathname: region.pathname.clone(),
					context_bytes,
				});
			}

			// Advance by chunk size minus overlap to avoid missing cross-boundary matches
			let advance = if read_size > overlap {
				read_size - overlap
			} else {
				read_size
			};
			offset += advance as u64;
		}
	}

	Ok(matches)
}

#[cfg(test)]
mod tests {
	use super::*;

	// parse_meminfo_kb tests

	#[test]
	fn test_parse_meminfo_kb_normal() {
		let content = "MemTotal:       16384000 kB\nMemFree:         8192000 kB\n";
		assert_eq!(parse_meminfo_kb(content, "MemTotal:"), 16384000);
		assert_eq!(parse_meminfo_kb(content, "MemFree:"), 8192000);
	}

	#[test]
	fn test_parse_meminfo_kb_key_not_found() {
		let content = "MemTotal:       16384000 kB\n";
		assert_eq!(parse_meminfo_kb(content, "MemFree:"), 0);
	}

	#[test]
	fn test_parse_meminfo_kb_non_numeric() {
		let content = "MemTotal:       abc kB\n";
		assert_eq!(parse_meminfo_kb(content, "MemTotal:"), 0);
	}

	#[test]
	fn test_parse_meminfo_kb_substring_key() {
		// "MemTotal:" should not match "MemTotalHuge:" because starts_with is exact
		let content = "MemTotalHuge:   1024 kB\nMemTotal:       16384000 kB\n";
		assert_eq!(parse_meminfo_kb(content, "MemTotal:"), 16384000);
	}

	// parse_maps_line tests

	#[test]
	fn test_parse_maps_line_full_mapped_file() {
		let line = "7f0e12345000-7f0e12346000 r-xp 00000000 08:01 12345  /usr/lib/libc.so.6";
		let region = parse_maps_line(line).unwrap();
		assert_eq!(region.start_address, 0x7f0e12345000);
		assert_eq!(region.end_address, 0x7f0e12346000);
		assert_eq!(region.permissions, "r-xp");
		assert_eq!(region.offset, 0);
		assert_eq!(region.device, "08:01");
		assert_eq!(region.inode, 12345);
		assert_eq!(region.pathname.as_deref(), Some("/usr/lib/libc.so.6"));
	}

	#[test]
	fn test_parse_maps_line_anonymous() {
		let line = "7f0e12345000-7f0e12346000 rw-p 00000000 00:00 0";
		let region = parse_maps_line(line).unwrap();
		assert_eq!(region.permissions, "rw-p");
		assert_eq!(region.inode, 0);
		assert!(region.pathname.is_none());
	}

	#[test]
	fn test_parse_maps_line_stack() {
		let line =
			"7ffd12345000-7ffd12366000 rw-p 00000000 00:00 0                          [stack]";
		let region = parse_maps_line(line).unwrap();
		assert_eq!(region.pathname.as_deref(), Some("[stack]"));
	}

	#[test]
	fn test_parse_maps_line_heap() {
		let line =
			"55a012345000-55a012366000 rw-p 00000000 00:00 0                          [heap]";
		let region = parse_maps_line(line).unwrap();
		assert_eq!(region.pathname.as_deref(), Some("[heap]"));
	}

	#[test]
	fn test_parse_maps_line_pathname_with_spaces() {
		let line = "7f0e12345000-7f0e12346000 r-xp 00000000 08:01 12345  /opt/My App/lib.so";
		let region = parse_maps_line(line).unwrap();
		assert_eq!(region.pathname.as_deref(), Some("/opt/My App/lib.so"));
	}

	#[test]
	fn test_parse_maps_line_empty() {
		assert!(parse_maps_line("").is_none());
	}

	#[test]
	fn test_parse_maps_line_no_dash_in_range() {
		let line = "7f0e12345000 r-xp 00000000 08:01 12345";
		assert!(parse_maps_line(line).is_none());
	}

	#[test]
	fn test_parse_maps_line_with_offset() {
		let line = "7f0e12345000-7f0e12346000 r--p 0001f000 08:01 12345  /usr/lib/libc.so.6";
		let region = parse_maps_line(line).unwrap();
		assert_eq!(region.offset, 0x1f000);
	}

	// pattern_to_bytes tests

	#[test]
	fn test_pattern_to_bytes_raw() {
		let pat = SearchPattern::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]);
		let (bytes, mask) = pattern_to_bytes(&pat);
		assert_eq!(bytes, vec![0xDE, 0xAD, 0xBE, 0xEF]);
		assert!(mask.is_none());
	}

	#[test]
	fn test_pattern_to_bytes_utf8() {
		let pat = SearchPattern::Utf8("hello".into());
		let (bytes, mask) = pattern_to_bytes(&pat);
		assert_eq!(bytes, b"hello".to_vec());
		assert!(mask.is_none());
	}

	#[test]
	fn test_pattern_to_bytes_utf16() {
		let pat = SearchPattern::Utf16("AB".into());
		let (bytes, mask) = pattern_to_bytes(&pat);
		// 'A' = 0x0041 LE -> [0x41, 0x00], 'B' = 0x0042 LE -> [0x42, 0x00]
		assert_eq!(bytes, vec![0x41, 0x00, 0x42, 0x00]);
		assert!(mask.is_none());
	}

	#[test]
	fn test_pattern_to_bytes_utf16_empty() {
		let pat = SearchPattern::Utf16(String::new());
		let (bytes, _) = pattern_to_bytes(&pat);
		assert!(bytes.is_empty());
	}

	#[test]
	fn test_pattern_to_bytes_masked() {
		let pat = SearchPattern::MaskedBytes {
			pattern: vec![0x48, 0x8B, 0x00, 0x00],
			mask: vec![0xFF, 0xFF, 0x00, 0x00],
		};
		let (bytes, mask) = pattern_to_bytes(&pat);
		assert_eq!(bytes, vec![0x48, 0x8B, 0x00, 0x00]);
		assert_eq!(mask.unwrap(), vec![0xFF, 0xFF, 0x00, 0x00]);
	}

	// find_all_occurrences tests (exact matching)

	#[test]
	fn test_find_all_occurrences_basic() {
		let haystack = b"abcabcabc";
		let needle = b"abc";
		assert_eq!(find_all_occurrences(haystack, needle, None), vec![0, 3, 6]);
	}

	#[test]
	fn test_find_all_occurrences_overlapping() {
		let haystack = b"aaaa";
		let needle = b"aa";
		assert_eq!(find_all_occurrences(haystack, needle, None), vec![0, 1, 2]);
	}

	#[test]
	fn test_find_all_occurrences_no_match() {
		let haystack = b"abcdef";
		let needle = b"xyz";
		assert!(find_all_occurrences(haystack, needle, None).is_empty());
	}

	#[test]
	fn test_find_all_occurrences_empty_needle() {
		let haystack = b"abc";
		let needle = b"";
		assert!(find_all_occurrences(haystack, needle, None).is_empty());
	}

	#[test]
	fn test_find_all_occurrences_needle_larger_than_haystack() {
		let haystack = b"ab";
		let needle = b"abc";
		assert!(find_all_occurrences(haystack, needle, None).is_empty());
	}

	#[test]
	fn test_find_all_occurrences_single_byte() {
		let haystack = b"a.b.c";
		let needle = b".";
		assert_eq!(find_all_occurrences(haystack, needle, None), vec![1, 3]);
	}

	// find_all_occurrences tests (masked matching)

	#[test]
	fn test_find_masked_single_wildcard() {
		// Pattern: 0x41 ?? 0x43 -- matches "A?C" where ? is any byte
		let haystack = b"ABCADCAXC";
		let needle = &[0x41, 0x00, 0x43];
		let mask = &[0xFF, 0x00, 0xFF];
		assert_eq!(
			find_all_occurrences(haystack, needle, Some(mask)),
			vec![0, 3, 6]
		);
	}

	#[test]
	fn test_find_masked_multiple_wildcards() {
		// Pattern: 0x7F ?? ?? 0x46 -- matches ELF magic with wildcard class/data bytes
		let haystack = &[0x7F, 0x45, 0x4C, 0x46, 0x00, 0x7F, 0x01, 0x02, 0x46];
		let needle = &[0x7F, 0x00, 0x00, 0x46];
		let mask = &[0xFF, 0x00, 0x00, 0xFF];
		assert_eq!(
			find_all_occurrences(haystack, needle, Some(mask)),
			vec![0, 5]
		);
	}

	#[test]
	fn test_find_masked_all_wildcards() {
		// All wildcard mask -- matches every position
		let haystack = b"abc";
		let needle = &[0x00];
		let mask = &[0x00];
		assert_eq!(
			find_all_occurrences(haystack, needle, Some(mask)),
			vec![0, 1, 2]
		);
	}

	#[test]
	fn test_find_masked_no_match() {
		let haystack = b"AABBCC";
		let needle = &[0xFF, 0x00, 0xFF];
		let mask = &[0xFF, 0x00, 0xFF];
		assert!(find_all_occurrences(haystack, needle, Some(mask)).is_empty());
	}

	#[test]
	fn test_find_masked_exact_fallback() {
		// All-0xFF mask is equivalent to exact matching
		let haystack = b"abcabc";
		let needle = b"abc";
		let mask = &[0xFF, 0xFF, 0xFF];
		assert_eq!(
			find_all_occurrences(haystack, needle, Some(mask)),
			vec![0, 3]
		);
	}

	// permissions_match tests

	#[test]
	fn test_permissions_match_empty_filter() {
		assert!(permissions_match("r-xp", ""));
	}

	#[test]
	fn test_permissions_match_read() {
		assert!(permissions_match("r-xp", "r"));
	}

	#[test]
	fn test_permissions_match_read_write() {
		assert!(permissions_match("rw-p", "rw"));
		assert!(!permissions_match("r--p", "rw"));
	}

	#[test]
	fn test_permissions_match_execute() {
		assert!(permissions_match("r-xp", "rx"));
		assert!(!permissions_match("rw-p", "x"));
	}
}
