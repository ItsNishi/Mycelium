//! Tunable parameters via Windows registry.
//!
//! Maps sysctl-style keys to well-known registry paths:
//! - `net.ipv4.*` -> `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`
//! - `net.ipv6.*` -> `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`
//! - `kernel.*`   -> `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager`

use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE};

use mycelium_core::error::{MyceliumError, Result};
use mycelium_core::types::{TunableParam, TunableValue};

/// Known registry path mappings from sysctl-style prefixes.
const TUNABLE_MAPPINGS: &[(&str, &str)] = &[
	(
		"net.ipv4",
		r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
	),
	(
		"net.ipv6",
		r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters",
	),
	(
		"net.netbt",
		r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters",
	),
	(
		"net.winsock",
		r"SYSTEM\CurrentControlSet\Services\AFD\Parameters",
	),
	(
		"net.dns",
		r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
	),
	(
		"kernel",
		r"SYSTEM\CurrentControlSet\Control\Session Manager",
	),
	(
		"kernel.memory",
		r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
	),
	(
		"kernel.crash",
		r"SYSTEM\CurrentControlSet\Control\CrashControl",
	),
	("kernel.power", r"SYSTEM\CurrentControlSet\Control\Power"),
	(
		"kernel.filesystem",
		r"SYSTEM\CurrentControlSet\Control\FileSystem",
	),
	("kernel.lsa", r"SYSTEM\CurrentControlSet\Control\Lsa"),
];

/// Resolve a sysctl-style key to (registry_path, value_name).
///
/// Supports `registry.SYSTEM\Path\To\Key.ValueName` for raw registry access.
fn resolve_key(key: &str) -> Result<(&str, String)> {
	// Handle `registry.` prefix for raw registry path access
	if let Some(rest) = key.strip_prefix("registry.") {
		// Find last dot to split path and value name
		if let Some(dot_pos) = rest.rfind('.') {
			let reg_path = &rest[..dot_pos];
			let value_name = rest[dot_pos + 1..].to_string();
			if reg_path.is_empty() || value_name.is_empty() {
				return Err(MyceliumError::NotFound(format!(
					"invalid registry key format: {key} (expected registry.PATH.ValueName)"
				)));
			}
			// Safety: reg_path borrows from `key` (via `rest`), which is the input &str
			return Ok((reg_path, value_name));
		}
		return Err(MyceliumError::NotFound(format!(
			"invalid registry key format: {key} (expected registry.PATH.ValueName)"
		)));
	}

	// Find the longest matching prefix
	let mut best_match: Option<(&str, &str)> = None;
	for &(prefix, reg_path) in TUNABLE_MAPPINGS {
		if key.starts_with(prefix)
			&& best_match
				.map(|(p, _)| prefix.len() > p.len())
				.unwrap_or(true)
		{
			best_match = Some((prefix, reg_path));
		}
	}

	let (prefix, reg_path) = best_match
		.ok_or_else(|| MyceliumError::NotFound(format!("no registry mapping for key: {key}")))?;

	// The value name is everything after the prefix (strip leading dot)
	let value_name = key[prefix.len()..].trim_start_matches('.').to_string();
	if value_name.is_empty() {
		return Err(MyceliumError::NotFound(format!(
			"key '{key}' resolves to a path prefix, not a specific value"
		)));
	}

	Ok((reg_path, value_name))
}

pub fn get_tunable(key: &str) -> Result<TunableValue> {
	let (reg_path, value_name) = resolve_key(key)?;

	let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
	let subkey = hklm
		.open_subkey_with_flags(reg_path, KEY_READ)
		.map_err(|e| MyceliumError::NotFound(format!("registry key {reg_path}: {e}")))?;

	// Try DWORD first, then string
	if let Ok(v) = subkey.get_value::<u32, _>(&value_name) {
		return Ok(TunableValue::Integer(v as i64));
	}

	if let Ok(v) = subkey.get_value::<String, _>(&value_name) {
		return Ok(TunableValue::String(v));
	}

	Err(MyceliumError::NotFound(format!(
		"registry value '{value_name}' not found in {reg_path}"
	)))
}

fn enumerate_registry_key(reg_path: &str, key_prefix: &str, tunables: &mut Vec<TunableParam>) {
	let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
	let subkey = match hklm.open_subkey_with_flags(reg_path, KEY_READ) {
		Ok(k) => k,
		Err(_) => return,
	};

	for value_name in subkey.enum_values().filter_map(|v| v.ok()) {
		let key = format!("{key_prefix}.{}", value_name.0);

		let value = match value_name.1.vtype {
			winreg::enums::RegType::REG_DWORD => {
				if value_name.1.bytes.len() >= 4 {
					let n = u32::from_le_bytes([
						value_name.1.bytes[0],
						value_name.1.bytes[1],
						value_name.1.bytes[2],
						value_name.1.bytes[3],
					]);
					TunableValue::Integer(n as i64)
				} else {
					continue;
				}
			}
			winreg::enums::RegType::REG_SZ | winreg::enums::RegType::REG_EXPAND_SZ => {
				let s = String::from_utf16_lossy(
					&value_name
						.1
						.bytes
						.chunks_exact(2)
						.map(|c| u16::from_le_bytes([c[0], c[1]]))
						.collect::<Vec<_>>(),
				)
				.trim_end_matches('\0')
				.to_string();
				TunableValue::String(s)
			}
			_ => continue,
		};

		tunables.push(TunableParam {
			key,
			value,
			description: None,
		});
	}
}

pub fn list_tunables(prefix: &str) -> Result<Vec<TunableParam>> {
	let mut tunables = Vec::new();

	// Handle `registry.` prefix — enumerate the specified registry key directly
	if let Some(rest) = prefix.strip_prefix("registry.") {
		if !rest.is_empty() {
			enumerate_registry_key(rest, prefix, &mut tunables);
		}
		return Ok(tunables);
	}

	for &(map_prefix, reg_path) in TUNABLE_MAPPINGS {
		if !prefix.is_empty() && !map_prefix.starts_with(prefix) {
			continue;
		}

		enumerate_registry_key(reg_path, map_prefix, &mut tunables);
	}

	Ok(tunables)
}

pub fn set_tunable(key: &str, value: &TunableValue) -> Result<TunableValue> {
	let (reg_path, value_name) = resolve_key(key)?;

	let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
	let subkey = hklm
		.open_subkey_with_flags(reg_path, KEY_SET_VALUE)
		.map_err(|e| {
			MyceliumError::PermissionDenied(format!("cannot open {reg_path} for writing: {e}"))
		})?;

	match value {
		TunableValue::Integer(n) => {
			subkey
				.set_value(&value_name, &(*n as u32))
				.map_err(|e| MyceliumError::OsError {
					code: e.raw_os_error().unwrap_or(-1),
					message: format!("set_value {value_name}: {e}"),
				})?;
		}
		TunableValue::String(s) => {
			subkey
				.set_value(&value_name, s)
				.map_err(|e| MyceliumError::OsError {
					code: e.raw_os_error().unwrap_or(-1),
					message: format!("set_value {value_name}: {e}"),
				})?;
		}
		TunableValue::Boolean(b) => {
			let dword: u32 = if *b { 1 } else { 0 };
			subkey
				.set_value(&value_name, &dword)
				.map_err(|e| MyceliumError::OsError {
					code: e.raw_os_error().unwrap_or(-1),
					message: format!("set_value {value_name}: {e}"),
				})?;
		}
	}

	// Read back the value to confirm
	get_tunable(key)
}

#[cfg(test)]
mod tests {
	use super::*;

	// -- resolve_key --

	#[test]
	fn test_resolve_key_ipv4() {
		let (path, value) = resolve_key("net.ipv4.TcpTimedWaitDelay").unwrap();
		assert_eq!(path, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters");
		assert_eq!(value, "TcpTimedWaitDelay");
	}

	#[test]
	fn test_resolve_key_kernel_memory() {
		// "kernel.memory" is more specific than "kernel" — longest match should win
		let (path, value) = resolve_key("kernel.memory.LargeSystemCache").unwrap();
		assert_eq!(
			path,
			r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
		);
		assert_eq!(value, "LargeSystemCache");
	}

	#[test]
	fn test_resolve_key_kernel_base() {
		let (path, value) = resolve_key("kernel.GlobalFlag").unwrap();
		assert_eq!(path, r"SYSTEM\CurrentControlSet\Control\Session Manager");
		assert_eq!(value, "GlobalFlag");
	}

	#[test]
	fn test_resolve_key_crash() {
		let (path, value) = resolve_key("kernel.crash.CrashDumpEnabled").unwrap();
		assert_eq!(path, r"SYSTEM\CurrentControlSet\Control\CrashControl");
		assert_eq!(value, "CrashDumpEnabled");
	}

	#[test]
	fn test_resolve_key_winsock() {
		let (path, value) = resolve_key("net.winsock.DefaultSendWindow").unwrap();
		assert_eq!(path, r"SYSTEM\CurrentControlSet\Services\AFD\Parameters");
		assert_eq!(value, "DefaultSendWindow");
	}

	#[test]
	fn test_resolve_key_dns() {
		let (path, value) = resolve_key("net.dns.MaxCacheTtl").unwrap();
		assert_eq!(
			path,
			r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
		);
		assert_eq!(value, "MaxCacheTtl");
	}

	#[test]
	fn test_resolve_key_lsa() {
		let (path, value) = resolve_key("kernel.lsa.RunAsPPL").unwrap();
		assert_eq!(path, r"SYSTEM\CurrentControlSet\Control\Lsa");
		assert_eq!(value, "RunAsPPL");
	}

	#[test]
	fn test_resolve_key_unknown_prefix() {
		assert!(resolve_key("storage.something").is_err());
	}

	#[test]
	fn test_resolve_key_prefix_only() {
		// Just a prefix with no value name should fail
		assert!(resolve_key("net.ipv4").is_err());
	}

	// -- resolve_key with registry. prefix --

	#[test]
	fn test_resolve_key_registry_prefix() {
		let (path, value) =
			resolve_key(r"registry.SYSTEM\CurrentControlSet\Control\Lsa.RunAsPPL").unwrap();
		assert_eq!(path, r"SYSTEM\CurrentControlSet\Control\Lsa");
		assert_eq!(value, "RunAsPPL");
	}

	#[test]
	fn test_resolve_key_registry_no_dot() {
		// No dot separator between path and value name
		assert!(resolve_key("registry.JustAPath").is_err());
	}

	#[test]
	fn test_resolve_key_registry_empty_value() {
		// Empty value name after last dot
		assert!(resolve_key("registry.SYSTEM\\Path.").is_err());
	}

	#[test]
	fn test_resolve_key_registry_empty_path() {
		assert!(resolve_key("registry..ValueName").is_err());
	}
}
