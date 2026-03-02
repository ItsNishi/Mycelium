//! Mycelium error types.

use core::fmt;

/// Convenience alias used throughout the crate.
pub type Result<T> = core::result::Result<T, MyceliumError>;

/// All error variants that Mycelium operations can produce.
#[derive(Debug)]
pub enum MyceliumError {
	/// The caller lacks the required privileges.
	PermissionDenied(String),
	/// The requested resource does not exist.
	NotFound(String),
	/// An OS-level error with its raw error code.
	OsError { code: i32, message: String },
	/// Failed to parse OS output into a structured type.
	ParseError(String),
	/// The operation is not supported on this platform.
	Unsupported(String),
	/// Wrapper around `std::io::Error`.
	IoError(std::io::Error),
	/// The operation was skipped because dry-run mode is active.
	DryRun(String),
	/// The operation timed out.
	Timeout(String),
	/// An eBPF probe error.
	ProbeError(String),
	/// Configuration error (invalid policy, bad TOML, etc.).
	ConfigError(String),
	/// Policy denied the operation.
	PolicyDenied { tool: String, reason: String },
}

impl fmt::Display for MyceliumError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::PermissionDenied(msg) => write!(f, "permission denied: {msg}"),
			Self::NotFound(msg) => write!(f, "not found: {msg}"),
			Self::OsError { code, message } => write!(f, "OS error {code}: {message}"),
			Self::ParseError(msg) => write!(f, "parse error: {msg}"),
			Self::Unsupported(msg) => write!(f, "unsupported: {msg}"),
			Self::IoError(err) => write!(f, "I/O error: {err}"),
			Self::DryRun(msg) => write!(f, "dry-run: {msg}"),
			Self::Timeout(msg) => write!(f, "timeout: {msg}"),
			Self::ProbeError(msg) => write!(f, "probe error: {msg}"),
			Self::ConfigError(msg) => write!(f, "config error: {msg}"),
			Self::PolicyDenied { tool, reason } => {
				write!(f, "policy denied tool '{tool}': {reason}")
			}
		}
	}
}

impl std::error::Error for MyceliumError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::IoError(err) => Some(err),
			_ => None,
		}
	}
}

impl From<std::io::Error> for MyceliumError {
	fn from(err: std::io::Error) -> Self {
		Self::IoError(err)
	}
}

