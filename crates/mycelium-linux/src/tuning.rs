//! Kernel tunable queries via /proc/sys.

use mycelium_core::error::{MyceliumError, Result};
use mycelium_core::types::*;
use std::fs;
use std::path::{Path, PathBuf};

/// Validate that a sysctl key doesn't allow path traversal.
fn validate_sysctl_key(key: &str) -> Result<()> {
	if key.is_empty() {
		return Err(MyceliumError::ParseError("empty sysctl key".into()));
	}
	for component in key.split('.') {
		if component.is_empty()
			|| component == ".."
			|| component.contains('/')
			|| component.contains('\\')
			|| component.contains('\0')
		{
			return Err(MyceliumError::ParseError(format!(
				"invalid sysctl key: {key}"
			)));
		}
	}
	Ok(())
}

/// Convert a sysctl key (dot-separated) to a /proc/sys path.
fn sysctl_path(key: &str) -> PathBuf {
	let mut path = PathBuf::from("/proc/sys");
	for component in key.split('.') {
		path.push(component);
	}
	path
}

/// Convert a /proc/sys path back to a sysctl key.
fn path_to_key(path: &Path) -> String {
	path.strip_prefix("/proc/sys")
		.unwrap_or(path)
		.to_string_lossy()
		.replace('/', ".")
}

/// Parse the raw string value into a TunableValue.
fn parse_value(raw: &str) -> TunableValue {
	let trimmed = raw.trim();

	// Try integer first
	if let Ok(n) = trimmed.parse::<i64>() {
		// 0 or 1 could be boolean in sysctl context, but we store as Integer
		// since the caller can interpret as needed
		return TunableValue::Integer(n);
	}

	TunableValue::String(trimmed.to_string())
}

pub fn get_tunable(key: &str) -> Result<TunableValue> {
	validate_sysctl_key(key)?;
	let path = sysctl_path(key);

	if !path.exists() {
		return Err(MyceliumError::NotFound(format!("tunable {key}")));
	}

	if !path.is_file() {
		return Err(MyceliumError::ParseError(format!(
			"{key} is a directory, not a tunable"
		)));
	}

	let content = fs::read_to_string(&path).map_err(|e| {
		if e.kind() == std::io::ErrorKind::PermissionDenied {
			MyceliumError::PermissionDenied(format!("cannot read {key}"))
		} else {
			MyceliumError::IoError(e)
		}
	})?;

	Ok(parse_value(&content))
}

pub fn list_tunables(prefix: &str) -> Result<Vec<TunableParam>> {
	if !prefix.is_empty() {
		validate_sysctl_key(prefix)?;
	}
	let base_path = if prefix.is_empty() {
		PathBuf::from("/proc/sys")
	} else {
		sysctl_path(prefix)
	};

	if !base_path.exists() {
		return Err(MyceliumError::NotFound(format!("tunable prefix {prefix}")));
	}

	let mut params = Vec::new();
	collect_tunables(&base_path, &mut params);
	params.sort_by(|a, b| a.key.cmp(&b.key));
	Ok(params)
}

fn collect_tunables(path: &Path, out: &mut Vec<TunableParam>) {
	if path.is_file() {
		let key = path_to_key(path);
		if let Ok(content) = fs::read_to_string(path) {
			out.push(TunableParam {
				key,
				value: parse_value(&content),
				description: None,
			});
		}
		return;
	}

	if path.is_dir()
		&& let Ok(entries) = fs::read_dir(path)
	{
		for entry in entries.flatten() {
			collect_tunables(&entry.path(), out);
		}
	}
}

pub fn set_tunable(key: &str, value: &TunableValue) -> Result<TunableValue> {
	validate_sysctl_key(key)?;
	let path = sysctl_path(key);

	if !path.exists() {
		return Err(MyceliumError::NotFound(format!("tunable {key}")));
	}

	if !path.is_file() {
		return Err(MyceliumError::ParseError(format!(
			"{key} is a directory, not a tunable"
		)));
	}

	// Read the previous value before writing
	let previous = {
		let content = fs::read_to_string(&path).map_err(|e| {
			if e.kind() == std::io::ErrorKind::PermissionDenied {
				MyceliumError::PermissionDenied(format!("cannot read {key}"))
			} else {
				MyceliumError::IoError(e)
			}
		})?;
		parse_value(&content)
	};

	let write_str = match value {
		TunableValue::String(s) => s.clone(),
		TunableValue::Integer(n) => n.to_string(),
		TunableValue::Boolean(b) => if *b { "1" } else { "0" }.to_string(),
	};

	fs::write(&path, format!("{write_str}\n")).map_err(|e| {
		if e.kind() == std::io::ErrorKind::PermissionDenied {
			MyceliumError::PermissionDenied(format!("cannot write {key} (run as root)"))
		} else {
			MyceliumError::IoError(e)
		}
	})?;

	Ok(previous)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_sysctl_path() {
		assert_eq!(
			sysctl_path("net.ipv4.ip_forward"),
			PathBuf::from("/proc/sys/net/ipv4/ip_forward")
		);
	}

	#[test]
	fn test_path_to_key() {
		let path = Path::new("/proc/sys/net/ipv4/ip_forward");
		assert_eq!(path_to_key(path), "net.ipv4.ip_forward");
	}

	#[test]
	fn test_sysctl_round_trip() {
		let key = "net.ipv4.ip_forward";
		assert_eq!(path_to_key(&sysctl_path(key)), key);
	}

	#[test]
	fn test_parse_value_integer() {
		assert_eq!(parse_value("42"), TunableValue::Integer(42));
	}

	#[test]
	fn test_parse_value_large_integer() {
		assert_eq!(
			parse_value("9223372036854775807"),
			TunableValue::Integer(i64::MAX)
		);
	}

	#[test]
	fn test_parse_value_string() {
		assert_eq!(
			parse_value("cubic"),
			TunableValue::String("cubic".to_string())
		);
	}
}
