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
