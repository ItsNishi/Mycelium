//! Handle enumeration via NtQuerySystemInformation.

use std::sync::mpsc;
use std::time::Duration;

use windows::Win32::Foundation::{CloseHandle, DUPLICATE_SAME_ACCESS, HANDLE};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcess, PROCESS_DUP_HANDLE};

use mycelium_core::error::{MyceliumError, Result};
use mycelium_core::types::HandleInfo;

// ---------------------------------------------------------------------------
// NT API constants
// ---------------------------------------------------------------------------

const SYSTEM_HANDLE_INFORMATION: u32 = 16;
const OBJECT_TYPE_INFORMATION: u32 = 2;
const OBJECT_NAME_INFORMATION: u32 = 1;
const STATUS_INFO_LENGTH_MISMATCH: i32 = -1073741820i32; // 0xC0000004
const MAX_HANDLES: usize = 100_000;
const INITIAL_BUFFER_SIZE: usize = 1024 * 1024; // 1 MiB
const MAX_BUFFER_SIZE: usize = 64 * 1024 * 1024; // 64 MiB

/// Timeout for querying object names that might hang.
const NAME_QUERY_TIMEOUT: Duration = Duration::from_millis(100);

// ---------------------------------------------------------------------------
// NT API structs (not in the windows crate)
// ---------------------------------------------------------------------------

#[repr(C)]
struct SystemHandleTableEntryInfo {
	process_id: u16,
	creator_back_trace_index: u16,
	object_type_index: u8,
	handle_attributes: u8,
	handle_value: u16,
	object: usize,
	granted_access: u32,
}

#[repr(C)]
struct SystemHandleInformationData {
	number_of_handles: u32,
	// Followed by a variable-length array of SystemHandleTableEntryInfo.
}

#[repr(C)]
struct UnicodeString {
	length: u16,
	maximum_length: u16,
	buffer: *mut u16,
}

#[repr(C)]
struct ObjectTypeInformation {
	type_name: UnicodeString,
	// Remaining fields are padding/reserved -- we only need the type name.
}

// ---------------------------------------------------------------------------
// NT API imports (ntdll)
// ---------------------------------------------------------------------------

#[link(name = "ntdll")]
unsafe extern "system" {
	fn NtQuerySystemInformation(
		system_information_class: u32,
		system_information: *mut u8,
		system_information_length: u32,
		return_length: *mut u32,
	) -> i32; // NTSTATUS

	fn NtQueryObject(
		handle: HANDLE,
		object_information_class: u32,
		object_information: *mut u8,
		object_information_length: u32,
		return_length: *mut u32,
	) -> i32; // NTSTATUS

	fn NtDuplicateObject(
		source_process_handle: HANDLE,
		source_handle: HANDLE,
		target_process_handle: HANDLE,
		target_handle: *mut HANDLE,
		desired_access: u32,
		handle_attributes: u32,
		options: u32,
	) -> i32; // NTSTATUS
}

// ---------------------------------------------------------------------------
// SafeHandle RAII wrapper
// ---------------------------------------------------------------------------

/// RAII guard for a Windows HANDLE. Automatically calls `CloseHandle` on drop.
struct SafeHandle(HANDLE);

impl Drop for SafeHandle {
	fn drop(&mut self) {
		unsafe {
			let _ = CloseHandle(self.0);
		}
	}
}

impl SafeHandle {
	/// Get the raw HANDLE value.
	fn raw(&self) -> HANDLE {
		self.0
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read a `UnicodeString` from an NT API buffer into a Rust `String`.
///
/// # Safety
/// The caller must ensure `us` points to a valid `UnicodeString` whose buffer
/// is readable for `length` bytes.
unsafe fn unicode_string_to_string(us: &UnicodeString) -> String {
	if us.length == 0 || us.buffer.is_null() {
		return String::new();
	}
	let len_u16 = us.length as usize / 2;
	let slice = unsafe { std::slice::from_raw_parts(us.buffer, len_u16) };
	String::from_utf16_lossy(slice)
}

/// Query the type name of an NT object via `NtQueryObject(ObjectTypeInformation)`.
fn query_object_type(handle: HANDLE) -> Option<String> {
	let mut buf = vec![0u8; 1024];
	let mut return_length: u32 = 0;

	let status = unsafe {
		NtQueryObject(
			handle,
			OBJECT_TYPE_INFORMATION,
			buf.as_mut_ptr(),
			buf.len() as u32,
			&mut return_length,
		)
	};

	if status < 0 {
		return None;
	}

	let oti = unsafe { &*(buf.as_ptr() as *const ObjectTypeInformation) };
	let name = unsafe { unicode_string_to_string(&oti.type_name) };
	if name.is_empty() { None } else { Some(name) }
}

/// Query the object name via `NtQueryObject(ObjectNameInformation)`.
///
/// This can hang indefinitely on certain object types (named pipes, ALPC
/// ports), so it is run on a helper thread with a timeout.
fn query_object_name_with_timeout(handle: HANDLE) -> Option<String> {
	// SAFETY: HANDLE is a raw pointer-sized value that is safe to send across
	// threads. The duplicated handle is valid for the lifetime of this call.
	let handle_value = handle.0 as usize;

	let (tx, rx) = mpsc::channel();

	std::thread::spawn(move || {
		let h = HANDLE(handle_value as *mut _);
		let result = query_object_name_inner(h);
		let _ = tx.send(result);
	});

	rx.recv_timeout(NAME_QUERY_TIMEOUT).unwrap_or_default()
}

/// Inner name query -- called from the timeout thread.
fn query_object_name_inner(handle: HANDLE) -> Option<String> {
	let mut buf = vec![0u8; 2048];
	let mut return_length: u32 = 0;

	let status = unsafe {
		NtQueryObject(
			handle,
			OBJECT_NAME_INFORMATION,
			buf.as_mut_ptr(),
			buf.len() as u32,
			&mut return_length,
		)
	};

	if status < 0 {
		return None;
	}

	// ObjectNameInformation returns a UNICODE_STRING at the start of the buffer.
	let us = unsafe { &*(buf.as_ptr() as *const UnicodeString) };
	let name = unsafe { unicode_string_to_string(us) };
	if name.is_empty() { None } else { Some(name) }
}

/// Returns `true` for object types that are known to hang on name queries.
fn type_may_hang(type_name: &str) -> bool {
	matches!(type_name, "File" | "ALPC Port")
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Enumerate all open handles for the process identified by `pid`.
///
/// This works by calling `NtQuerySystemInformation(SystemHandleInformation)`
/// to obtain the full system handle table, filtering to the target process,
/// and then duplicating each handle into the current process for inspection.
///
/// Handles that cannot be duplicated or queried are silently skipped.
pub(crate) fn list_process_handles(pid: u32) -> Result<Vec<HandleInfo>> {
	// The SystemHandleInformation class uses a u16 process_id field, so PIDs
	// above 65535 cannot be matched. Fall back to the extended variant or
	// report an error.
	if pid > u16::MAX as u32 {
		return Err(MyceliumError::Unsupported(format!(
			"process ID {pid} exceeds the u16 limit of SystemHandleInformation; \
			 SystemExtendedHandleInformation (class 64) is required but not yet implemented"
		)));
	}

	let _ = crate::privilege::ensure_debug_privilege();

	// -----------------------------------------------------------------
	// 1. Query the full system handle table
	// -----------------------------------------------------------------
	let handle_data = query_system_handle_information()?;

	// -----------------------------------------------------------------
	// 2. Parse and filter entries for the target PID
	// -----------------------------------------------------------------
	let entries = parse_handle_entries(&handle_data, pid as u16);

	if entries.is_empty() {
		return Ok(Vec::new());
	}

	// -----------------------------------------------------------------
	// 3. Open the target process for handle duplication
	// -----------------------------------------------------------------
	let target_process = unsafe { OpenProcess(PROCESS_DUP_HANDLE, false, pid) }
		.map_err(|e| MyceliumError::PermissionDenied(format!("cannot open process {pid}: {e}")))?;
	let target_process = SafeHandle(target_process);
	let current_process = unsafe { GetCurrentProcess() };

	// -----------------------------------------------------------------
	// 4. Duplicate, query, and collect results
	// -----------------------------------------------------------------
	let mut results = Vec::new();

	for entry in &entries {
		if results.len() >= MAX_HANDLES {
			tracing::warn!(
				pid,
				count = results.len(),
				"reached maximum handle limit, stopping enumeration"
			);
			break;
		}

		// Duplicate the handle into our process
		let mut dup_handle = HANDLE::default();
		let status = unsafe {
			NtDuplicateObject(
				target_process.raw(),
				HANDLE(entry.handle_value as usize as *mut _),
				current_process,
				&mut dup_handle,
				0,
				0,
				DUPLICATE_SAME_ACCESS.0,
			)
		};

		if status < 0 {
			// Cannot duplicate -- access denied, handle invalid, etc.
			continue;
		}

		let dup = SafeHandle(dup_handle);

		// Query object type
		let object_type = match query_object_type(dup.raw()) {
			Some(t) => t,
			None => {
				continue;
			}
		};

		// Query object name (with hang-safety)
		let name = if type_may_hang(&object_type) {
			None
		} else {
			query_object_name_with_timeout(dup.raw())
		};

		results.push(HandleInfo {
			handle_value: entry.handle_value as u64,
			object_type,
			name,
			access_mask: entry.granted_access,
		});
	}

	Ok(results)
}

/// Call `NtQuerySystemInformation(SystemHandleInformation)` with a growing
/// buffer until the call succeeds or the maximum size is exceeded.
fn query_system_handle_information() -> Result<Vec<u8>> {
	let mut buf_size = INITIAL_BUFFER_SIZE;

	loop {
		let mut buffer = vec![0u8; buf_size];
		let mut return_length: u32 = 0;

		let status = unsafe {
			NtQuerySystemInformation(
				SYSTEM_HANDLE_INFORMATION,
				buffer.as_mut_ptr(),
				buf_size as u32,
				&mut return_length,
			)
		};

		if status == STATUS_INFO_LENGTH_MISMATCH {
			// Buffer too small -- double it and retry.
			buf_size *= 2;
			if buf_size > MAX_BUFFER_SIZE {
				return Err(MyceliumError::OsError {
					code: status,
					message: format!(
						"NtQuerySystemInformation buffer exceeded {MAX_BUFFER_SIZE} bytes"
					),
				});
			}
			continue;
		}

		if status < 0 {
			return Err(MyceliumError::OsError {
				code: status,
				message: format!(
					"NtQuerySystemInformation(SystemHandleInformation) failed: NTSTATUS 0x{:08X}",
					status as u32
				),
			});
		}

		// Success -- shrink buffer to actual length if available.
		if return_length > 0 && (return_length as usize) < buffer.len() {
			buffer.truncate(return_length as usize);
		}

		return Ok(buffer);
	}
}

/// Parse the raw buffer returned by `NtQuerySystemInformation` into a slice
/// of `SystemHandleTableEntryInfo` entries filtered by the target PID.
fn parse_handle_entries(buffer: &[u8], target_pid: u16) -> Vec<SystemHandleTableEntryInfo> {
	if buffer.len() < std::mem::size_of::<SystemHandleInformationData>() {
		return Vec::new();
	}

	let header = unsafe { &*(buffer.as_ptr() as *const SystemHandleInformationData) };
	let count = header.number_of_handles as usize;

	let entries_offset = std::mem::size_of::<SystemHandleInformationData>();
	let entry_size = std::mem::size_of::<SystemHandleTableEntryInfo>();

	// Validate that the buffer is large enough for the declared entry count.
	let required = entries_offset + count * entry_size;
	if buffer.len() < required {
		tracing::warn!(
			declared = count,
			buffer_len = buffer.len(),
			required,
			"handle table buffer smaller than expected, clamping entry count"
		);
	}

	let max_entries = (buffer.len() - entries_offset) / entry_size;
	let safe_count = count.min(max_entries);

	let entries_ptr =
		unsafe { buffer.as_ptr().add(entries_offset) } as *const SystemHandleTableEntryInfo;

	let mut result = Vec::new();

	for i in 0..safe_count {
		// Use read_unaligned because the entries array starts at offset 4
		// (after the u32 count header), which may not be aligned for usize.
		let entry = unsafe { entries_ptr.add(i).read_unaligned() };
		if entry.process_id == target_pid {
			result.push(entry);
		}
	}

	result
}

#[cfg(test)]
mod tests {
	use super::*;

	// -- SafeHandle --

	#[test]
	fn test_safe_handle_raw_roundtrip() {
		// Use an invalid but non-null handle value to test the wrapper
		// (we never close it because INVALID_HANDLE_VALUE is -1).
		let sentinel = HANDLE(-1isize as *mut _);
		let sh = SafeHandle(sentinel);
		assert_eq!(sh.raw().0, sentinel.0);
		// Prevent the Drop from running on an invalid sentinel.
		std::mem::forget(sh);
	}

	// -- type_may_hang --

	#[test]
	fn test_type_may_hang_file() {
		assert!(type_may_hang("File"));
	}

	#[test]
	fn test_type_may_hang_alpc() {
		assert!(type_may_hang("ALPC Port"));
	}

	#[test]
	fn test_type_may_hang_event() {
		assert!(!type_may_hang("Event"));
	}

	#[test]
	fn test_type_may_hang_key() {
		assert!(!type_may_hang("Key"));
	}

	#[test]
	fn test_type_may_hang_empty() {
		assert!(!type_may_hang(""));
	}

	// -- parse_handle_entries --

	#[test]
	fn test_parse_handle_entries_empty_buffer() {
		let buf = vec![0u8; 4]; // Just a zeroed header with count = 0
		let entries = parse_handle_entries(&buf, 1);
		assert!(entries.is_empty());
	}

	#[test]
	fn test_parse_handle_entries_filters_by_pid() {
		// Build a minimal buffer with a header and two entries.
		let entry_size = std::mem::size_of::<SystemHandleTableEntryInfo>();
		let header_size = std::mem::size_of::<SystemHandleInformationData>();
		let total = header_size + 2 * entry_size;
		let mut buf = vec![0u8; total];

		// Write count = 2
		buf[0] = 2;

		// Entry 0: pid = 42
		let entry0_offset = header_size;
		buf[entry0_offset] = 42; // process_id low byte
		buf[entry0_offset + 1] = 0; // process_id high byte

		// Entry 1: pid = 99
		let entry1_offset = header_size + entry_size;
		buf[entry1_offset] = 99;
		buf[entry1_offset + 1] = 0;

		let entries = parse_handle_entries(&buf, 42);
		assert_eq!(entries.len(), 1);
		assert_eq!(entries[0].process_id, 42);

		let entries = parse_handle_entries(&buf, 99);
		assert_eq!(entries.len(), 1);
		assert_eq!(entries[0].process_id, 99);

		let entries = parse_handle_entries(&buf, 1);
		assert!(entries.is_empty());
	}

	#[test]
	fn test_parse_handle_entries_truncated_buffer() {
		// Header claims 100 entries but the buffer only has room for 1.
		let entry_size = std::mem::size_of::<SystemHandleTableEntryInfo>();
		let header_size = std::mem::size_of::<SystemHandleInformationData>();
		let total = header_size + entry_size;
		let mut buf = vec![0u8; total];

		// Write count = 100 (overcount)
		buf[0] = 100;

		// The single entry has pid = 7
		let entry_offset = header_size;
		buf[entry_offset] = 7;

		let entries = parse_handle_entries(&buf, 7);
		assert_eq!(entries.len(), 1);
	}

	// -- PID u16 limit --

	#[test]
	fn test_pid_exceeds_u16_max() {
		let result = list_process_handles(u16::MAX as u32 + 1);
		assert!(result.is_err());
		let err = result.unwrap_err();
		let msg = format!("{err}");
		assert!(msg.contains("u16 limit"), "unexpected error: {msg}");
	}
}
