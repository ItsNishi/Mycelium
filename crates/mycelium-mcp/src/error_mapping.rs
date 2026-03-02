//! Maps raw OS errors to actionable agent-facing messages.
//!
//! Audit logging continues to use the raw `Display` output so operators see
//! the unmodified error. The mapped message is only shown to MCP agents.

use mycelium_core::error::MyceliumError;

/// Optional context passed alongside an error to refine the message.
pub struct ErrorContext {
	pub pid: Option<u32>,
}

/// Produce an agent-friendly message for a `MyceliumError`.
///
/// The returned string is what MCP agents see. Audit logs should continue
/// using `err.to_string()` so operators get the raw detail.
pub fn map_error_message(err: &MyceliumError, ctx: Option<&ErrorContext>) -> String {
	match err {
		MyceliumError::OsError { code, message } => map_os_error(*code, message),

		MyceliumError::PermissionDenied(msg) => {
			if let Some(ctx) = ctx {
				if ctx.pid == Some(0) {
					return "Access denied — PID 0 is the System Idle Process and cannot be inspected".to_string();
				}
				if ctx.pid == Some(4) {
					return "Access denied — PID 4 is the System process and cannot be inspected by user-mode tools".to_string();
				}
			}
			format!("{msg} — try running with administrator elevation")
		}

		MyceliumError::NotFound(msg) => {
			format!("not found: {msg} — the process may have exited, refresh and retry")
		}

		MyceliumError::PolicyDenied { tool, reason } => {
			format!("policy denied tool '{tool}': {reason} — check agent's policy profile")
		}

		MyceliumError::Timeout(msg) => {
			format!("timeout: {msg} — target may be unresponsive")
		}

		// All other variants pass through unchanged.
		other => other.to_string(),
	}
}

/// Map a Windows OS error code to an actionable message.
fn map_os_error(code: i32, original: &str) -> String {
	// If the code is a negative HRESULT, try to extract the Win32 code.
	let win32_code = if code < 0 {
		extract_win32_from_hresult(code)
	} else {
		Some(code)
	};

	match win32_code {
		Some(5) => "Access denied — try running with administrator elevation".to_string(),
		Some(299) => {
			"Partial read/write — target memory may be partially unmapped".to_string()
		}
		Some(998) => {
			"Invalid memory address — check region is committed with correct protection"
				.to_string()
		}
		_ => format!("OS error {code}: {original}"),
	}
}

/// Extract a Win32 error code from a FACILITY_WIN32 HRESULT.
///
/// HRESULT layout: bit 31 = severity, bits 16-26 = facility, bits 0-15 = code.
/// FACILITY_WIN32 = 7. If the HRESULT encodes a Win32 code, return it.
fn extract_win32_from_hresult(hr: i32) -> Option<i32> {
	let hr = hr as u32;
	let facility = (hr >> 16) & 0x7FF;
	if facility == 7 {
		// FACILITY_WIN32
		Some((hr & 0xFFFF) as i32)
	} else {
		None
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_os_error_code_5() {
		let err = MyceliumError::OsError {
			code: 5,
			message: "Access is denied.".into(),
		};
		let msg = map_error_message(&err, None);
		assert!(msg.contains("administrator elevation"), "got: {msg}");
	}

	#[test]
	fn test_os_error_code_299() {
		let err = MyceliumError::OsError {
			code: 299,
			message: "Only part of a ReadProcessMemory or WriteProcessMemory request was completed.".into(),
		};
		let msg = map_error_message(&err, None);
		assert!(msg.contains("partially unmapped"), "got: {msg}");
	}

	#[test]
	fn test_os_error_code_998() {
		let err = MyceliumError::OsError {
			code: 998,
			message: "Invalid access to memory location.".into(),
		};
		let msg = map_error_message(&err, None);
		assert!(msg.contains("committed with correct protection"), "got: {msg}");
	}

	#[test]
	fn test_hresult_unwrap_facility_win32() {
		// HRESULT for ERROR_ACCESS_DENIED (5) = 0x80070005
		let hresult = 0x80070005_u32 as i32;
		let err = MyceliumError::OsError {
			code: hresult,
			message: "HRESULT wrapped access denied".into(),
		};
		let msg = map_error_message(&err, None);
		assert!(msg.contains("administrator elevation"), "got: {msg}");
	}

	#[test]
	fn test_permission_denied_pid_0() {
		let err = MyceliumError::PermissionDenied("cannot open process 0".into());
		let ctx = ErrorContext { pid: Some(0) };
		let msg = map_error_message(&err, Some(&ctx));
		assert!(msg.contains("System Idle Process"), "got: {msg}");
	}

	#[test]
	fn test_permission_denied_pid_4() {
		let err = MyceliumError::PermissionDenied("cannot open process 4".into());
		let ctx = ErrorContext { pid: Some(4) };
		let msg = map_error_message(&err, Some(&ctx));
		assert!(msg.contains("System process"), "got: {msg}");
	}

	#[test]
	fn test_not_found_append() {
		let err = MyceliumError::NotFound("process 12345".into());
		let msg = map_error_message(&err, None);
		assert!(msg.contains("may have exited"), "got: {msg}");
	}

	#[test]
	fn test_policy_denied_append() {
		let err = MyceliumError::PolicyDenied {
			tool: "process_kill".into(),
			reason: "read-only profile".into(),
		};
		let msg = map_error_message(&err, None);
		assert!(msg.contains("policy profile"), "got: {msg}");
	}

	#[test]
	fn test_timeout_append() {
		let err = MyceliumError::Timeout("WMI query".into());
		let msg = map_error_message(&err, None);
		assert!(msg.contains("unresponsive"), "got: {msg}");
	}

	#[test]
	fn test_unknown_os_error_passthrough() {
		let err = MyceliumError::OsError {
			code: 9999,
			message: "something unusual".into(),
		};
		let msg = map_error_message(&err, None);
		assert_eq!(msg, "OS error 9999: something unusual");
	}

	#[test]
	fn test_other_variant_passthrough() {
		let err = MyceliumError::Unsupported("not on Windows".into());
		let msg = map_error_message(&err, None);
		assert_eq!(msg, "unsupported: not on Windows");
	}
}
