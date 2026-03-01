/// Log types.

/// A single log entry.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LogEntry {
	pub timestamp: u64,
	pub level: LogLevel,
	pub unit: Option<String>,
	pub message: String,
	pub pid: Option<u32>,
	pub source: Option<String>,
}

/// Log severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum LogLevel {
	Emergency,
	Alert,
	Critical,
	Error,
	Warning,
	Notice,
	Info,
	Debug,
}

/// Query parameters for log retrieval.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LogQuery {
	pub unit: Option<String>,
	pub level: Option<LogLevel>,
	pub since: Option<u64>,
	pub until: Option<u64>,
	pub limit: Option<u32>,
	pub grep: Option<String>,
}
