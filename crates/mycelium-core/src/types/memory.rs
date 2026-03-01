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
