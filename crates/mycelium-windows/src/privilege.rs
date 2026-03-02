//! Windows privilege management — SeDebugPrivilege, elevation detection, and
//! token privilege enumeration.

use std::sync::OnceLock;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
	CloseHandle, GetLastError, HANDLE, HLOCAL, LUID, LocalFree, WIN32_ERROR,
};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{
	AdjustTokenPrivileges, GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation,
	IsTokenRestricted, LookupAccountSidW, LookupPrivilegeNameW, LookupPrivilegeValueW,
	LUID_AND_ATTRIBUTES, PSID, SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED, SID_AND_ATTRIBUTES,
	SID_NAME_USE, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_GROUPS,
	TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER,
	TokenElevation, TokenElevationType, TokenGroups, TokenImpersonationLevel,
	TokenIntegrityLevel, TokenPrivileges, TokenSessionId, TokenType as TokenTypeClass, TokenUser,
};
use windows::Win32::System::Threading::{
	GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION,
};

use mycelium_core::error::{MyceliumError, Result};
use mycelium_core::types::{PrivilegeInfo, TokenGroup, TokenInfo};

/// Returns `true` if the current process is running elevated (as admin).
#[allow(dead_code)]
pub(crate) fn is_elevated() -> bool {
	unsafe {
		let mut token = HANDLE::default();
		if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
			return false;
		}

		let mut elevation = TOKEN_ELEVATION {
			TokenIsElevated: 0,
		};
		let mut return_length = 0u32;
		let ok = GetTokenInformation(
			token,
			TokenElevation,
			Some(&mut elevation as *mut _ as *mut _),
			std::mem::size_of::<TOKEN_ELEVATION>() as u32,
			&mut return_length,
		);

		let _ = CloseHandle(token);
		ok.is_ok() && elevation.TokenIsElevated != 0
	}
}

/// Enables `SeDebugPrivilege` on the current process token.
pub(crate) fn enable_debug_privilege() -> Result<()> {
	unsafe {
		let mut token = HANDLE::default();
		OpenProcessToken(
			GetCurrentProcess(),
			TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
			&mut token,
		)
		.map_err(|e| MyceliumError::PermissionDenied(format!("OpenProcessToken: {e}")))?;

		let mut luid = LUID::default();
		if let Err(e) = LookupPrivilegeValueW(None, SE_DEBUG_NAME, &mut luid) {
			let _ = CloseHandle(token);
			return Err(MyceliumError::PermissionDenied(format!(
				"LookupPrivilegeValue: {e}"
			)));
		}

		let tp = TOKEN_PRIVILEGES {
			PrivilegeCount: 1,
			Privileges: [LUID_AND_ATTRIBUTES {
				Luid: luid,
				Attributes: SE_PRIVILEGE_ENABLED,
			}],
		};

		let result = AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None);
		let last_err = GetLastError();
		let _ = CloseHandle(token);

		result.map_err(|e| {
			MyceliumError::PermissionDenied(format!("AdjustTokenPrivileges: {e}"))
		})?;

		if last_err != WIN32_ERROR(0) {
			return Err(MyceliumError::PermissionDenied(
				"SeDebugPrivilege not granted (not running as admin?)".to_string(),
			));
		}

		Ok(())
	}
}

/// Cached one-shot wrapper: enables `SeDebugPrivilege` once, returns the
/// cached result on subsequent calls.
pub(crate) fn ensure_debug_privilege() -> Result<()> {
	static RESULT: OnceLock<std::result::Result<(), String>> = OnceLock::new();

	let cached = RESULT.get_or_init(|| enable_debug_privilege().map_err(|e| e.to_string()));

	cached
		.as_ref()
		.map(|_| ())
		.map_err(|msg| MyceliumError::PermissionDenied(msg.clone()))
}

/// Resolve a privilege LUID to its display name (e.g. `"SeDebugPrivilege"`).
fn lookup_privilege_name(luid: &LUID) -> String {
	unsafe {
		// First call: determine required buffer length
		let mut name_len = 0u32;
		let _ = LookupPrivilegeNameW(PCWSTR::null(), luid, None, &mut name_len);

		if name_len == 0 {
			return format!("{}:{}", luid.HighPart, luid.LowPart);
		}

		let mut name_buf = vec![0u16; name_len as usize];
		if LookupPrivilegeNameW(
			PCWSTR::null(),
			luid,
			Some(PWSTR(name_buf.as_mut_ptr())),
			&mut name_len,
		)
		.is_ok()
		{
			String::from_utf16_lossy(&name_buf[..name_len as usize])
		} else {
			format!("{}:{}", luid.HighPart, luid.LowPart)
		}
	}
}

/// Enumerate all privileges held by a process token.
///
/// Opens the target process, queries its token for `TokenPrivileges`, and
/// resolves each LUID to a privilege name via `LookupPrivilegeNameW`.
pub(crate) fn enumerate_token_privileges(pid: u32) -> Result<Vec<PrivilegeInfo>> {
	unsafe {
		// Open the target process
		let process = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid).map_err(|e| {
			MyceliumError::OsError {
				code: e.code().0,
				message: format!("OpenProcess({pid}) failed: {e}"),
			}
		})?;

		// Open the process token
		let mut token = HANDLE::default();
		let result = OpenProcessToken(process, TOKEN_QUERY, &mut token);
		let _ = CloseHandle(process);
		result.map_err(|e| MyceliumError::OsError {
			code: e.code().0,
			message: format!("OpenProcessToken({pid}) failed: {e}"),
		})?;

		// First call: get required buffer size
		let mut needed = 0u32;
		let _ = GetTokenInformation(token, TokenPrivileges, None, 0, &mut needed);

		if needed == 0 {
			let _ = CloseHandle(token);
			return Ok(Vec::new());
		}

		// Second call: fill the buffer
		let mut buffer = vec![0u8; needed as usize];
		let ok = GetTokenInformation(
			token,
			TokenPrivileges,
			Some(buffer.as_mut_ptr() as *mut _),
			needed,
			&mut needed,
		);

		if let Err(e) = ok {
			let _ = CloseHandle(token);
			return Err(MyceliumError::OsError {
				code: e.code().0,
				message: format!("GetTokenInformation(TokenPrivileges) failed: {e}"),
			});
		}

		let tp = &*(buffer.as_ptr() as *const TOKEN_PRIVILEGES);
		let privileges = std::slice::from_raw_parts(
			tp.Privileges.as_ptr(),
			tp.PrivilegeCount as usize,
		);

		let mut result = Vec::with_capacity(privileges.len());

		for entry in privileges {
			let name = lookup_privilege_name(&entry.Luid);
			let enabled = entry.Attributes.contains(SE_PRIVILEGE_ENABLED);
			result.push(PrivilegeInfo { name, enabled });
		}

		let _ = CloseHandle(token);
		Ok(result)
	}
}

// ---------------------------------------------------------------------------
// Token inspection
// ---------------------------------------------------------------------------

/// Maximum number of groups we will read from a token.
const MAX_GROUPS: usize = 256;

/// Two-pass helper: calls `GetTokenInformation` once with a zero-length buffer
/// to learn the required size, then allocates and calls again.
unsafe fn get_token_info_buffer(
	token: HANDLE,
	class: TOKEN_INFORMATION_CLASS,
) -> Result<Vec<u8>> {
	let mut needed = 0u32;
	let _ = unsafe { GetTokenInformation(token, class, None, 0, &mut needed) };

	if needed == 0 {
		return Err(MyceliumError::OsError {
			code: 0,
			message: format!("GetTokenInformation({class:?}) returned zero size"),
		});
	}

	let mut buffer = vec![0u8; needed as usize];
	unsafe {
		GetTokenInformation(
			token,
			class,
			Some(buffer.as_mut_ptr() as *mut _),
			needed,
			&mut needed,
		)
	}
	.map_err(|e| MyceliumError::OsError {
		code: e.code().0,
		message: format!("GetTokenInformation({class:?}) failed: {e}"),
	})?;

	Ok(buffer)
}

/// Resolve a `PSID` to a `"DOMAIN\User"` string via the two-pass
/// `LookupAccountSidW` pattern.
unsafe fn resolve_sid_to_account(sid: PSID) -> Option<String> {
	let mut name_len = 0u32;
	let mut domain_len = 0u32;
	let mut use_kind = SID_NAME_USE::default();

	// First pass: get required sizes.
	let _ = unsafe {
		LookupAccountSidW(
			PCWSTR::null(),
			sid,
			None,
			&mut name_len,
			None,
			&mut domain_len,
			&mut use_kind,
		)
	};

	if name_len == 0 {
		return None;
	}

	let mut name_buf = vec![0u16; name_len as usize];
	let mut domain_buf = vec![0u16; domain_len as usize];

	unsafe {
		LookupAccountSidW(
			PCWSTR::null(),
			sid,
			Some(PWSTR(name_buf.as_mut_ptr())),
			&mut name_len,
			Some(PWSTR(domain_buf.as_mut_ptr())),
			&mut domain_len,
			&mut use_kind,
		)
	}
	.ok()?;

	let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
	let domain = String::from_utf16_lossy(&domain_buf[..domain_len as usize]);

	if domain.is_empty() {
		Some(name)
	} else {
		Some(format!("{domain}\\{name}"))
	}
}

/// Convert a `PSID` to its string form (e.g. `"S-1-5-18"`) via
/// `ConvertSidToStringSidW`. The allocated `PWSTR` is freed with `LocalFree`.
unsafe fn sid_to_string(sid: PSID) -> Option<String> {
	let mut string_sid = PWSTR::null();
	unsafe { ConvertSidToStringSidW(sid, &mut string_sid) }.ok()?;

	let result = unsafe { string_sid.to_string() }.ok();
	let _ = unsafe { LocalFree(Some(HLOCAL(string_sid.0 as *mut _))) };
	result
}

/// Decode the group-attributes bitmask into human-readable labels.
fn decode_group_attributes(attrs: u32) -> Vec<String> {
	let mut out = Vec::new();
	if attrs & 0x1 != 0 {
		out.push("Mandatory".to_string());
	}
	if attrs & 0x2 != 0 {
		out.push("EnabledByDefault".to_string());
	}
	if attrs & 0x4 != 0 {
		out.push("Enabled".to_string());
	}
	if attrs & 0x8 != 0 {
		out.push("Owner".to_string());
	}
	if attrs & 0x10 != 0 {
		out.push("UseForDenyOnly".to_string());
	}
	if attrs & 0x20 != 0 {
		out.push("Integrity".to_string());
	}
	if attrs & 0xC000_0000 != 0 {
		out.push("LogonId".to_string());
	}
	out
}

/// Open a process token and extract comprehensive security information.
///
/// Returns a [`TokenInfo`] containing the token user, integrity level, type,
/// elevation details, session id, groups, and privileges.
pub(crate) fn inspect_process_token(pid: u32) -> Result<TokenInfo> {
	unsafe {
		// Open the target process.
		let process = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid).map_err(|e| {
			MyceliumError::OsError {
				code: e.code().0,
				message: format!("OpenProcess({pid}) failed: {e}"),
			}
		})?;

		// Open the process token.
		let mut token = HANDLE::default();
		let res = OpenProcessToken(process, TOKEN_QUERY, &mut token);
		let _ = CloseHandle(process);
		res.map_err(|e| MyceliumError::OsError {
			code: e.code().0,
			message: format!("OpenProcessToken({pid}) failed: {e}"),
		})?;

		// ---- TokenUser → "DOMAIN\User" ------------------------------------
		let user = get_token_info_buffer(token, TokenUser)
			.ok()
			.and_then(|buf| {
				let tu = &*(buf.as_ptr() as *const TOKEN_USER);
				resolve_sid_to_account(tu.User.Sid)
			})
			.unwrap_or_else(|| "<unknown>".to_string());

		// ---- TokenIntegrityLevel ------------------------------------------
		let integrity_level = get_token_info_buffer(token, TokenIntegrityLevel)
			.ok()
			.map(|buf| {
				let label = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
				let sid = label.Label.Sid;
				let sub_count = *GetSidSubAuthorityCount(sid);
				if sub_count == 0 {
					return "Unknown".to_string();
				}
				let rid = *GetSidSubAuthority(sid, (sub_count - 1) as u32);
				match rid {
					0x0000 => "Untrusted".to_string(),
					0x1000 => "Low".to_string(),
					0x2000 => "Medium".to_string(),
					0x2100 => "MediumPlus".to_string(),
					0x3000 => "High".to_string(),
					0x4000 => "System".to_string(),
					other => format!("Unknown(0x{other:04X})"),
				}
			})
			.unwrap_or_else(|| "Unknown".to_string());

		// ---- TokenType ----------------------------------------------------
		let token_type_raw = get_token_info_buffer(token, TokenTypeClass)
			.ok()
			.map(|buf| *(buf.as_ptr() as *const u32))
			.unwrap_or(0);

		let token_type = match token_type_raw {
			1 => "Primary".to_string(),
			2 => "Impersonation".to_string(),
			_ => format!("Unknown({token_type_raw})"),
		};

		// ---- TokenImpersonationLevel (only for impersonation tokens) ------
		let impersonation_level = if token_type_raw == 2 {
			get_token_info_buffer(token, TokenImpersonationLevel)
				.ok()
				.map(|buf| {
					let val = *(buf.as_ptr() as *const u32);
					match val {
						0 => "Anonymous".to_string(),
						1 => "Identification".to_string(),
						2 => "Impersonation".to_string(),
						3 => "Delegation".to_string(),
						other => format!("Unknown({other})"),
					}
				})
		} else {
			None
		};

		// ---- TokenElevationType -------------------------------------------
		let elevation_type = get_token_info_buffer(token, TokenElevationType)
			.ok()
			.map(|buf| {
				let val = *(buf.as_ptr() as *const u32);
				match val {
					1 => "Default".to_string(),
					2 => "Full".to_string(),
					3 => "Limited".to_string(),
					other => format!("Unknown({other})"),
				}
			})
			.unwrap_or_else(|| "Unknown".to_string());

		// ---- TokenElevation (bool) ----------------------------------------
		let is_elevated = get_token_info_buffer(token, TokenElevation)
			.ok()
			.map(|buf| {
				let elev = &*(buf.as_ptr() as *const TOKEN_ELEVATION);
				elev.TokenIsElevated != 0
			})
			.unwrap_or(false);

		// ---- TokenSessionId -----------------------------------------------
		let session_id = get_token_info_buffer(token, TokenSessionId)
			.ok()
			.map(|buf| *(buf.as_ptr() as *const u32))
			.unwrap_or(0);

		// ---- TokenGroups --------------------------------------------------
		let groups = get_token_info_buffer(token, TokenGroups)
			.ok()
			.map(|buf| {
				let tg = &*(buf.as_ptr() as *const TOKEN_GROUPS);
				let count = (tg.GroupCount as usize).min(MAX_GROUPS);
				let entries =
					std::slice::from_raw_parts(tg.Groups.as_ptr(), count);

				entries
					.iter()
					.map(|sa: &SID_AND_ATTRIBUTES| {
						let name = resolve_sid_to_account(sa.Sid)
							.unwrap_or_else(|| "<unknown>".to_string());
						let sid_str =
							sid_to_string(sa.Sid).unwrap_or_default();
						let attributes =
							decode_group_attributes(sa.Attributes);
						TokenGroup {
							name,
							sid: sid_str,
							attributes,
						}
					})
					.collect::<Vec<_>>()
			})
			.unwrap_or_default();

		// ---- IsTokenRestricted --------------------------------------------
		let is_restricted = IsTokenRestricted(token).is_ok();

		// ---- Privileges ---------------------------------------------------
		let privileges = get_token_info_buffer(token, TokenPrivileges)
			.ok()
			.map(|buf| {
				let tp = &*(buf.as_ptr() as *const TOKEN_PRIVILEGES);
				let entries = std::slice::from_raw_parts(
					tp.Privileges.as_ptr(),
					tp.PrivilegeCount as usize,
				);
				entries
					.iter()
					.map(|entry| {
						let name = lookup_privilege_name(&entry.Luid);
						let enabled =
							entry.Attributes.contains(SE_PRIVILEGE_ENABLED);
						PrivilegeInfo { name, enabled }
					})
					.collect::<Vec<_>>()
			})
			.unwrap_or_default();

		let _ = CloseHandle(token);

		Ok(TokenInfo {
			pid,
			user,
			integrity_level,
			token_type,
			impersonation_level,
			elevation_type,
			is_elevated,
			is_restricted,
			session_id,
			groups,
			privileges,
		})
	}
}
