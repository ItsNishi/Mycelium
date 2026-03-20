//! Memory information via sysinfo and WinAPI.

use std::mem;

use sysinfo::{Pid, ProcessesToUpdate, System};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Memory::{
	MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE,
	PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS,
	PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, VirtualProtectEx,
	VirtualQueryEx,
};
use windows::Win32::System::ProcessStatus::GetMappedFileNameW;
use windows::Win32::System::Threading::{
	OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};

use mycelium_core::error::{MyceliumError, Result};
use mycelium_core::types::{
	MemoryInfo, MemoryMatch, MemoryRegion, MemorySearchOptions, ProcessMemory, SearchPattern,
	SwapInfo,
};

/// Maximum bytes for a single read_process_memory call (1 MiB).
const MAX_READ_SIZE: usize = 1024 * 1024;

/// Maximum bytes for a single write_process_memory call (1 MiB).
const MAX_WRITE_SIZE: usize = 1024 * 1024;

/// Chunk size for reading process memory during search (1 MiB).
const SEARCH_CHUNK_SIZE: usize = 1024 * 1024;

/// Hard cap on search matches.
const MAX_SEARCH_MATCHES: usize = 10_000;

/// Hard cap on context bytes around each match.
const MAX_CONTEXT_SIZE: usize = 256;

/// Skip regions larger than this during search (256 MiB).
const MAX_SEARCH_REGION_SIZE: usize = 256 * 1024 * 1024;

/// Maximum bytes for a single protect_process_memory call (16 MiB).
const MAX_PROTECT_SIZE: usize = 16 * 1024 * 1024;

/// RAII guard for a Windows process HANDLE. Automatically calls `CloseHandle` on drop.
struct SafeHandle(HANDLE);

impl Drop for SafeHandle {
	fn drop(&mut self) {
		unsafe {
			let _ = CloseHandle(self.0);
		}
	}
}

impl SafeHandle {
	/// Open a process with the given access rights, returning a SafeHandle.
	fn open_process(
		access: windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS,
		pid: u32,
	) -> std::result::Result<Self, windows::core::Error> {
		let handle = unsafe { OpenProcess(access, false, pid) }?;
		Ok(Self(handle))
	}

	/// Get the raw HANDLE value.
	fn raw(&self) -> HANDLE {
		self.0
	}
}

pub fn memory_info() -> Result<MemoryInfo> {
	let mut sys = System::new();
	sys.refresh_memory();

	Ok(MemoryInfo {
		total_bytes: sys.total_memory(),
		available_bytes: sys.available_memory(),
		used_bytes: sys.used_memory(),
		free_bytes: sys.free_memory(),
		buffers_bytes: 0, // Linux-specific
		cached_bytes: 0,  // Linux-specific
		swap: SwapInfo {
			total_bytes: sys.total_swap(),
			used_bytes: sys.used_swap(),
			free_bytes: sys.free_swap(),
		},
	})
}

/// Walk committed regions to compute (shared_bytes, text_bytes, data_bytes).
fn compute_memory_breakdown(handle: HANDLE) -> (u64, u64, u64) {
	let mut shared: u64 = 0;
	let mut text: u64 = 0;
	let mut data: u64 = 0;
	let mut address: usize = 0;
	let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { mem::zeroed() };
	let mbi_size = mem::size_of::<MEMORY_BASIC_INFORMATION>();

	loop {
		let written = unsafe {
			VirtualQueryEx(
				handle,
				Some(address as *const _),
				&mut mbi as *mut _,
				mbi_size,
			)
		};

		if written == 0 {
			break;
		}

		if mbi.State == MEM_COMMIT {
			let size = mbi.RegionSize as u64;
			let prot = mbi.Protect;
			let base_prot = PAGE_PROTECTION_FLAGS(prot.0 & !PAGE_GUARD.0);

			// shared = MEM_MAPPED or MEM_IMAGE
			if mbi.Type == MEM_MAPPED || mbi.Type == MEM_IMAGE {
				shared += size;
			}

			// text = executable regions
			if base_prot == PAGE_EXECUTE
				|| base_prot == PAGE_EXECUTE_READ
				|| base_prot == PAGE_EXECUTE_READWRITE
				|| base_prot == PAGE_EXECUTE_WRITECOPY
			{
				text += size;
			}

			// data = private read-write
			if mbi.Type == MEM_PRIVATE && base_prot == PAGE_READWRITE {
				data += size;
			}
		}

		let next = mbi.BaseAddress as usize + mbi.RegionSize;
		if next <= address {
			break;
		}
		address = next;
	}

	(shared, text, data)
}

pub fn process_memory(pid: u32) -> Result<ProcessMemory> {
	let mut sys = System::new();
	let sysinfo_pid = Pid::from_u32(pid);
	sys.refresh_processes(ProcessesToUpdate::Some(&[sysinfo_pid]), true);

	let proc = sys
		.process(sysinfo_pid)
		.ok_or_else(|| MyceliumError::NotFound(format!("process {pid}")))?;

	let (shared_bytes, text_bytes, data_bytes) = {
		let _ = crate::privilege::ensure_debug_privilege();
		match SafeHandle::open_process(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, pid) {
			Ok(handle) => compute_memory_breakdown(handle.raw()),
			Err(e) => {
				tracing::debug!(
					pid,
					error = %e,
					"OpenProcess failed for memory breakdown, returning zeros"
				);
				(0, 0, 0)
			}
		}
	};

	Ok(ProcessMemory {
		pid,
		rss_bytes: proc.memory(),
		virtual_bytes: proc.virtual_memory(),
		shared_bytes,
		text_bytes,
		data_bytes,
	})
}

fn protection_to_string(protect: PAGE_PROTECTION_FLAGS) -> String {
	let has_guard = protect.0 & PAGE_GUARD.0 != 0;
	let base = PAGE_PROTECTION_FLAGS(protect.0 & !PAGE_GUARD.0);
	let perms = if base == PAGE_NOACCESS {
		"---"
	} else if base == PAGE_READONLY {
		"r--"
	} else if base == PAGE_READWRITE || base == PAGE_WRITECOPY {
		"rw-"
	} else if base == PAGE_EXECUTE {
		"--x"
	} else if base == PAGE_EXECUTE_READ {
		"r-x"
	} else if base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY {
		"rwx"
	} else {
		"---"
	};
	if has_guard {
		format!("{perms}g")
	} else {
		format!("{perms}-")
	}
}

pub fn process_memory_maps(pid: u32) -> Result<Vec<MemoryRegion>> {
	let _ = crate::privilege::ensure_debug_privilege();

	let handle = SafeHandle::open_process(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, pid)
		.map_err(|e| MyceliumError::PermissionDenied(format!("cannot open process {pid}: {e}")))?;

	enumerate_regions(handle.raw())
}

fn enumerate_regions(handle: HANDLE) -> Result<Vec<MemoryRegion>> {
	let mut regions = Vec::new();
	let mut address: usize = 0;
	let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { mem::zeroed() };
	let mbi_size = mem::size_of::<MEMORY_BASIC_INFORMATION>();

	loop {
		let written = unsafe {
			VirtualQueryEx(
				handle,
				Some(address as *const _),
				&mut mbi as *mut _,
				mbi_size,
			)
		};

		if written == 0 {
			break;
		}

		if mbi.State == MEM_COMMIT {
			let start = mbi.BaseAddress as u64;
			let end = start + mbi.RegionSize as u64;

			let mut name_buf = [0u16; 512];
			let name_len =
				unsafe { GetMappedFileNameW(handle, address as *const _, &mut name_buf) };
			let pathname = if name_len > 0 {
				Some(String::from_utf16_lossy(&name_buf[..name_len as usize]))
			} else {
				None
			};

			regions.push(MemoryRegion {
				start_address: start,
				end_address: end,
				permissions: protection_to_string(mbi.Protect),
				offset: 0,
				device: "0:0".to_string(),
				inode: 0,
				pathname,
			});
		}

		let next = mbi.BaseAddress as usize + mbi.RegionSize;
		if next <= address {
			break;
		}
		address = next;
	}

	Ok(regions)
}

pub fn read_process_memory(pid: u32, address: u64, size: usize) -> Result<Vec<u8>> {
	if size > MAX_READ_SIZE {
		return Err(MyceliumError::Unsupported(format!(
			"read size {size} exceeds maximum of {MAX_READ_SIZE} bytes"
		)));
	}

	let _ = crate::privilege::ensure_debug_privilege();

	let handle = SafeHandle::open_process(PROCESS_VM_READ, pid)
		.map_err(|e| MyceliumError::PermissionDenied(format!("cannot open process {pid}: {e}")))?;

	let mut buffer = vec![0u8; size];
	let mut bytes_read: usize = 0;

	let ok = unsafe {
		ReadProcessMemory(
			handle.raw(),
			address as *const _,
			buffer.as_mut_ptr() as *mut _,
			size,
			Some(&mut bytes_read),
		)
	};

	ok.map_err(|e| MyceliumError::OsError {
		code: e.code().0,
		message: format!("ReadProcessMemory failed: {e}"),
	})?;

	buffer.truncate(bytes_read);
	Ok(buffer)
}

pub fn write_process_memory(pid: u32, address: u64, data: &[u8]) -> Result<usize> {
	if data.len() > MAX_WRITE_SIZE {
		return Err(MyceliumError::Unsupported(format!(
			"write size {} exceeds maximum of {MAX_WRITE_SIZE} bytes",
			data.len()
		)));
	}

	let _ = crate::privilege::ensure_debug_privilege();

	let handle = SafeHandle::open_process(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, pid)
		.map_err(|e| MyceliumError::PermissionDenied(format!("cannot open process {pid}: {e}")))?;

	let mut bytes_written: usize = 0;

	let ok = unsafe {
		WriteProcessMemory(
			handle.raw(),
			address as *const _,
			data.as_ptr() as *const _,
			data.len(),
			Some(&mut bytes_written),
		)
	};

	ok.map_err(|e| MyceliumError::OsError {
		code: e.code().0,
		message: format!("WriteProcessMemory failed: {e}"),
	})?;

	Ok(bytes_written)
}

fn parse_protection_string(s: &str) -> Result<PAGE_PROTECTION_FLAGS> {
	match s {
		"---" => Ok(PAGE_NOACCESS),
		"r--" => Ok(PAGE_READONLY),
		"rw-" => Ok(PAGE_READWRITE),
		"--x" => Ok(PAGE_EXECUTE),
		"r-x" => Ok(PAGE_EXECUTE_READ),
		"rwx" => Ok(PAGE_EXECUTE_READWRITE),
		_ => Err(MyceliumError::ParseError(format!(
			"invalid protection string: \"{s}\" (expected one of: ---, r--, rw-, --x, r-x, rwx)"
		))),
	}
}

fn protection_flags_to_string(flags: PAGE_PROTECTION_FLAGS) -> String {
	let base = PAGE_PROTECTION_FLAGS(flags.0 & !PAGE_GUARD.0);
	if base == PAGE_NOACCESS {
		"---".to_string()
	} else if base == PAGE_READONLY {
		"r--".to_string()
	} else if base == PAGE_READWRITE || base == PAGE_WRITECOPY {
		"rw-".to_string()
	} else if base == PAGE_EXECUTE {
		"--x".to_string()
	} else if base == PAGE_EXECUTE_READ {
		"r-x".to_string()
	} else if base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY {
		"rwx".to_string()
	} else {
		"---".to_string()
	}
}

pub fn protect_process_memory(
	pid: u32,
	address: u64,
	size: usize,
	protection: &str,
) -> Result<String> {
	if size == 0 {
		return Err(MyceliumError::Unsupported(
			"protect size must be greater than 0".to_string(),
		));
	}
	if size > MAX_PROTECT_SIZE {
		return Err(MyceliumError::Unsupported(format!(
			"protect size {size} exceeds maximum of {MAX_PROTECT_SIZE} bytes"
		)));
	}

	let new_protect = parse_protection_string(protection)?;

	let _ = crate::privilege::ensure_debug_privilege();

	let handle = SafeHandle::open_process(PROCESS_VM_OPERATION, pid)
		.map_err(|e| MyceliumError::PermissionDenied(format!("cannot open process {pid}: {e}")))?;

	let mut old_protect = PAGE_PROTECTION_FLAGS::default();

	let ok = unsafe {
		VirtualProtectEx(
			handle.raw(),
			address as *const _,
			size,
			new_protect,
			&mut old_protect,
		)
	};

	ok.map_err(|e| MyceliumError::OsError {
		code: e.code().0,
		message: format!("VirtualProtectEx failed: {e}"),
	})?;

	Ok(protection_flags_to_string(old_protect))
}

/// Convert a `SearchPattern` to raw bytes and an optional mask for matching.
///
/// Returns `(needle, mask)`. When `mask` is `None`, use exact byte matching.
/// When `mask` is `Some`, byte `i` matches if `(haystack[i] & mask[i]) == (needle[i] & mask[i])`.
fn pattern_to_bytes(pattern: &SearchPattern) -> (Vec<u8>, Option<Vec<u8>>) {
	match pattern {
		SearchPattern::Bytes(v) => (v.clone(), None),
		SearchPattern::Utf8(s) => (s.as_bytes().to_vec(), None),
		SearchPattern::Utf16(s) => {
			(s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect(), None)
		}
		SearchPattern::MaskedBytes { pattern, mask } => {
			(pattern.clone(), Some(mask.clone()))
		}
	}
}

/// Find all occurrences of `needle` in `haystack`, returning byte offsets.
///
/// When `mask` is `None`, performs exact matching (fast path).
/// When `mask` is `Some`, byte `i` matches if `(h & m) == (n & m)`.
fn find_all_occurrences(
	haystack: &[u8],
	needle: &[u8],
	mask: Option<&[u8]>,
) -> Vec<usize> {
	if needle.is_empty() || needle.len() > haystack.len() {
		return Vec::new();
	}
	let mut positions = Vec::new();

	match mask {
		None => {
			let mut i = 0;
			while i <= haystack.len() - needle.len() {
				if haystack[i..i + needle.len()] == *needle {
					positions.push(i);
				}
				i += 1;
			}
		}
		Some(m) => {
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

/// Check if a `PAGE_PROTECTION_FLAGS` value satisfies the given permission filter.
///
/// Filter chars: 'r' = readable, 'w' = writable, 'x' = executable.
/// Empty filter matches everything.
fn protection_matches(prot: PAGE_PROTECTION_FLAGS, filter: &str) -> bool {
	if filter.is_empty() {
		return true;
	}
	let base = PAGE_PROTECTION_FLAGS(prot.0 & !PAGE_GUARD.0);

	let is_readable = matches!(
		base,
		_ if base == PAGE_READONLY
			|| base == PAGE_READWRITE
			|| base == PAGE_WRITECOPY
			|| base == PAGE_EXECUTE_READ
			|| base == PAGE_EXECUTE_READWRITE
			|| base == PAGE_EXECUTE_WRITECOPY
	);
	let is_writable = matches!(
		base,
		_ if base == PAGE_READWRITE
			|| base == PAGE_WRITECOPY
			|| base == PAGE_EXECUTE_READWRITE
			|| base == PAGE_EXECUTE_WRITECOPY
	);
	let is_executable = matches!(
		base,
		_ if base == PAGE_EXECUTE
			|| base == PAGE_EXECUTE_READ
			|| base == PAGE_EXECUTE_READWRITE
			|| base == PAGE_EXECUTE_WRITECOPY
	);

	for c in filter.chars() {
		match c {
			'r' if !is_readable => return false,
			'w' if !is_writable => return false,
			'x' if !is_executable => return false,
			_ => {}
		}
	}
	true
}

pub fn search_process_memory(
	pid: u32,
	pattern: &SearchPattern,
	options: &MemorySearchOptions,
) -> Result<Vec<MemoryMatch>> {
	let (needle, mask) = pattern_to_bytes(pattern);
	if needle.is_empty() {
		return Err(MyceliumError::Unsupported(
			"search pattern must not be empty".to_string(),
		));
	}
	if let Some(ref m) = mask {
		if m.len() != needle.len() {
			return Err(MyceliumError::ParseError(
				"mask length must equal pattern length".into(),
			));
		}
	}

	let max_matches = options.max_matches.min(MAX_SEARCH_MATCHES);
	let context_size = options.context_size.min(MAX_CONTEXT_SIZE);

	let _ = crate::privilege::ensure_debug_privilege();

	let handle = SafeHandle::open_process(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, pid)
		.map_err(|e| MyceliumError::PermissionDenied(format!("cannot open process {pid}: {e}")))?;

	let mut matches = Vec::new();
	let mut address: usize = 0;
	let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { mem::zeroed() };
	let mbi_size = mem::size_of::<MEMORY_BASIC_INFORMATION>();

	loop {
		if matches.len() >= max_matches {
			break;
		}

		let written = unsafe {
			VirtualQueryEx(
				handle.raw(),
				Some(address as *const _),
				&mut mbi as *mut _,
				mbi_size,
			)
		};

		if written == 0 {
			break;
		}

		let region_start = mbi.BaseAddress as u64;
		let region_size = mbi.RegionSize;

		// Advance to the next region
		let next = mbi.BaseAddress as usize + region_size;
		if next <= address {
			break;
		}

		// Only scan committed regions that match the permissions filter
		if mbi.State == MEM_COMMIT
			&& protection_matches(mbi.Protect, &options.permissions_filter)
			&& region_size <= MAX_SEARCH_REGION_SIZE
			&& mbi.Protect != PAGE_NOACCESS
			&& mbi.Protect.0 & PAGE_GUARD.0 == 0
		{
			// Get region metadata for match results
			let perms = protection_to_string(mbi.Protect);
			let mut name_buf = [0u16; 512];
			let name_len =
				unsafe { GetMappedFileNameW(handle.raw(), address as *const _, &mut name_buf) };
			let pathname = if name_len > 0 {
				Some(String::from_utf16_lossy(&name_buf[..name_len as usize]))
			} else {
				None
			};

			// Read the region in chunks with overlap for cross-boundary matches
			let overlap = if needle.len() > 1 {
				needle.len() - 1
			} else {
				0
			};
			let mut chunk_offset: usize = 0;

			while chunk_offset < region_size && matches.len() < max_matches {
				let remaining = region_size - chunk_offset;
				let read_size = remaining.min(SEARCH_CHUNK_SIZE);

				let mut buffer = vec![0u8; read_size];
				let mut bytes_read: usize = 0;
				let read_addr = mbi.BaseAddress as usize + chunk_offset;

				let ok = unsafe {
					ReadProcessMemory(
						handle.raw(),
						read_addr as *const _,
						buffer.as_mut_ptr() as *mut _,
						read_size,
						Some(&mut bytes_read),
					)
				};

				if ok.is_err() || bytes_read == 0 {
					break;
				}

				buffer.truncate(bytes_read);

				let positions = find_all_occurrences(&buffer, &needle, mask.as_deref());

				for pos in positions {
					if matches.len() >= max_matches {
						break;
					}

					let abs_address = read_addr as u64 + pos as u64;

					// Read context bytes centered on the match
					let ctx_bytes = if context_size > 0 {
						let half = context_size / 2;
						let ctx_start = abs_address.saturating_sub(half as u64);
						let ctx_len = context_size
							.min((region_start + region_size as u64 - ctx_start) as usize);
						let mut ctx_buf = vec![0u8; ctx_len];
						let mut ctx_read: usize = 0;
						let _ = unsafe {
							ReadProcessMemory(
								handle.raw(),
								ctx_start as *const _,
								ctx_buf.as_mut_ptr() as *mut _,
								ctx_len,
								Some(&mut ctx_read),
							)
						};
						ctx_buf.truncate(ctx_read);
						ctx_buf
					} else {
						Vec::new()
					};

					matches.push(MemoryMatch {
						address: abs_address,
						region_start,
						region_permissions: perms.clone(),
						region_pathname: pathname.clone(),
						context_bytes: ctx_bytes,
					});
				}

				// Advance with overlap to catch cross-boundary matches
				if bytes_read < read_size || read_size == remaining {
					break;
				}
				chunk_offset += bytes_read - overlap;
			}
		}

		address = next;
	}

	Ok(matches)
}

#[cfg(test)]
mod tests {
	use super::*;

	// -- parse_protection_string --

	#[test]
	fn test_parse_protection_noaccess() {
		assert_eq!(parse_protection_string("---").unwrap(), PAGE_NOACCESS);
	}

	#[test]
	fn test_parse_protection_readonly() {
		assert_eq!(parse_protection_string("r--").unwrap(), PAGE_READONLY);
	}

	#[test]
	fn test_parse_protection_readwrite() {
		assert_eq!(parse_protection_string("rw-").unwrap(), PAGE_READWRITE);
	}

	#[test]
	fn test_parse_protection_execute() {
		assert_eq!(parse_protection_string("--x").unwrap(), PAGE_EXECUTE);
	}

	#[test]
	fn test_parse_protection_execute_read() {
		assert_eq!(parse_protection_string("r-x").unwrap(), PAGE_EXECUTE_READ);
	}

	#[test]
	fn test_parse_protection_execute_readwrite() {
		assert_eq!(
			parse_protection_string("rwx").unwrap(),
			PAGE_EXECUTE_READWRITE
		);
	}

	#[test]
	fn test_parse_protection_invalid() {
		assert!(parse_protection_string("xyz").is_err());
	}

	// -- protection_flags_to_string --

	#[test]
	fn test_flags_to_string_noaccess() {
		assert_eq!(protection_flags_to_string(PAGE_NOACCESS), "---");
	}

	#[test]
	fn test_flags_to_string_readonly() {
		assert_eq!(protection_flags_to_string(PAGE_READONLY), "r--");
	}

	#[test]
	fn test_flags_to_string_readwrite() {
		assert_eq!(protection_flags_to_string(PAGE_READWRITE), "rw-");
	}

	#[test]
	fn test_flags_to_string_writecopy() {
		assert_eq!(protection_flags_to_string(PAGE_WRITECOPY), "rw-");
	}

	#[test]
	fn test_flags_to_string_execute() {
		assert_eq!(protection_flags_to_string(PAGE_EXECUTE), "--x");
	}

	#[test]
	fn test_flags_to_string_execute_read() {
		assert_eq!(protection_flags_to_string(PAGE_EXECUTE_READ), "r-x");
	}

	#[test]
	fn test_flags_to_string_execute_readwrite() {
		assert_eq!(protection_flags_to_string(PAGE_EXECUTE_READWRITE), "rwx");
	}

	#[test]
	fn test_flags_to_string_execute_writecopy() {
		assert_eq!(protection_flags_to_string(PAGE_EXECUTE_WRITECOPY), "rwx");
	}

	// -- round-trip --

	#[test]
	fn test_protection_round_trip() {
		for perm in ["---", "r--", "rw-", "--x", "r-x", "rwx"] {
			let flags = parse_protection_string(perm).unwrap();
			assert_eq!(protection_flags_to_string(flags), perm);
		}
	}

	// -- pattern_to_bytes --

	#[test]
	fn test_pattern_to_bytes_raw() {
		let pat = SearchPattern::Bytes(vec![0x4d, 0x5a, 0x90, 0x00]);
		assert_eq!(pattern_to_bytes(&pat), vec![0x4d, 0x5a, 0x90, 0x00]);
	}

	#[test]
	fn test_pattern_to_bytes_utf8() {
		let pat = SearchPattern::Utf8("hello".to_string());
		assert_eq!(pattern_to_bytes(&pat), b"hello".to_vec());
	}

	#[test]
	fn test_pattern_to_bytes_utf16() {
		let pat = SearchPattern::Utf16("AB".to_string());
		// 'A' = 0x0041 LE -> [0x41, 0x00], 'B' = 0x0042 LE -> [0x42, 0x00]
		assert_eq!(pattern_to_bytes(&pat), vec![0x41, 0x00, 0x42, 0x00]);
	}

	#[test]
	fn test_pattern_to_bytes_utf16_emoji() {
		let pat = SearchPattern::Utf16("\u{1F600}".to_string());
		// U+1F600 encodes as surrogate pair: 0xD83D 0xDE00
		let expected: Vec<u8> = vec![0x3D, 0xD8, 0x00, 0xDE];
		assert_eq!(pattern_to_bytes(&pat), expected);
	}

	// -- find_all_occurrences --

	#[test]
	fn test_find_all_empty_needle() {
		assert_eq!(find_all_occurrences(b"hello", b""), Vec::<usize>::new());
	}

	#[test]
	fn test_find_all_no_match() {
		assert_eq!(find_all_occurrences(b"hello", b"xyz"), Vec::<usize>::new());
	}

	#[test]
	fn test_find_all_single_match() {
		assert_eq!(find_all_occurrences(b"hello world", b"world"), vec![6]);
	}

	#[test]
	fn test_find_all_multiple_matches() {
		assert_eq!(find_all_occurrences(b"abcabcabc", b"abc"), vec![0, 3, 6]);
	}

	#[test]
	fn test_find_all_overlapping_matches() {
		assert_eq!(find_all_occurrences(b"aaaa", b"aa"), vec![0, 1, 2]);
	}

	#[test]
	fn test_find_all_single_byte() {
		assert_eq!(find_all_occurrences(b"abba", b"b"), vec![1, 2]);
	}

	#[test]
	fn test_find_all_needle_longer_than_haystack() {
		assert_eq!(find_all_occurrences(b"ab", b"abcdef"), Vec::<usize>::new());
	}

	// -- protection_matches --

	#[test]
	fn test_protection_matches_empty_filter() {
		assert!(protection_matches(PAGE_NOACCESS, ""));
		assert!(protection_matches(PAGE_READWRITE, ""));
	}

	#[test]
	fn test_protection_matches_read_filter() {
		assert!(protection_matches(PAGE_READONLY, "r"));
		assert!(protection_matches(PAGE_READWRITE, "r"));
		assert!(protection_matches(PAGE_EXECUTE_READ, "r"));
		assert!(!protection_matches(PAGE_EXECUTE, "r"));
		assert!(!protection_matches(PAGE_NOACCESS, "r"));
	}

	#[test]
	fn test_protection_matches_write_filter() {
		assert!(protection_matches(PAGE_READWRITE, "w"));
		assert!(protection_matches(PAGE_EXECUTE_READWRITE, "w"));
		assert!(!protection_matches(PAGE_READONLY, "w"));
		assert!(!protection_matches(PAGE_EXECUTE_READ, "w"));
	}

	#[test]
	fn test_protection_matches_exec_filter() {
		assert!(protection_matches(PAGE_EXECUTE, "x"));
		assert!(protection_matches(PAGE_EXECUTE_READ, "x"));
		assert!(!protection_matches(PAGE_READONLY, "x"));
		assert!(!protection_matches(PAGE_READWRITE, "x"));
	}

	#[test]
	fn test_protection_matches_combined_rw() {
		assert!(protection_matches(PAGE_READWRITE, "rw"));
		assert!(protection_matches(PAGE_EXECUTE_READWRITE, "rw"));
		assert!(!protection_matches(PAGE_READONLY, "rw"));
		assert!(!protection_matches(PAGE_EXECUTE_READ, "rw"));
	}

	#[test]
	fn test_protection_matches_combined_rwx() {
		assert!(protection_matches(PAGE_EXECUTE_READWRITE, "rwx"));
		assert!(!protection_matches(PAGE_READWRITE, "rwx"));
		assert!(!protection_matches(PAGE_EXECUTE_READ, "rwx"));
	}
}
