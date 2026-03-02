//! Memory-related types.

/// System-wide memory information.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MemoryInfo {
	pub total_bytes: u64,
	pub available_bytes: u64,
	pub used_bytes: u64,
	pub free_bytes: u64,
	pub buffers_bytes: u64,
	pub cached_bytes: u64,
	pub swap: SwapInfo,
}

/// Swap usage.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SwapInfo {
	pub total_bytes: u64,
	pub used_bytes: u64,
	pub free_bytes: u64,
}

/// What to search for in process memory.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SearchPattern {
	/// Raw bytes (hex-encoded in MCP/CLI).
	Bytes(Vec<u8>),
	/// UTF-8 string.
	Utf8(String),
	/// UTF-16LE string.
	Utf16(String),
}

/// A single match found during memory search.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MemoryMatch {
	pub address: u64,
	pub region_start: u64,
	pub region_permissions: String,
	pub region_pathname: Option<String>,
	/// Bytes around the match for context (configurable window).
	pub context_bytes: Vec<u8>,
}

/// Options controlling memory search behavior.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MemorySearchOptions {
	/// Max matches before stopping (default 100).
	pub max_matches: usize,
	/// Bytes of context to capture around each match (default 32).
	pub context_size: usize,
	/// Only search regions with these permission chars (e.g. "rw" = readable+writable).
	/// Empty = search all committed regions.
	pub permissions_filter: String,
}

impl Default for MemorySearchOptions {
	fn default() -> Self {
		Self {
			max_matches: 100,
			context_size: 32,
			permissions_filter: String::new(),
		}
	}
}

/// A single region from a process's virtual memory map (`/proc/<pid>/maps`).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MemoryRegion {
	pub start_address: u64,
	pub end_address: u64,
	/// Permission string, e.g. "rwxp", "r-xp".
	pub permissions: String,
	pub offset: u64,
	/// Device major:minor, e.g. "08:01".
	pub device: String,
	pub inode: u64,
	/// Mapped file or label, e.g. "/lib/libc.so", "[heap]", "[stack]".
	pub pathname: Option<String>,
}
