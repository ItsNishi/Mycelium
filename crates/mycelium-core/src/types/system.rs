//! System-level types.

/// High-level system information.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SystemInfo {
	pub hostname: String,
	pub os_name: String,
	pub os_version: String,
	pub architecture: String,
	pub uptime_seconds: u64,
	pub boot_time: u64,
}

/// Kernel information.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KernelInfo {
	pub version: String,
	pub release: String,
	pub architecture: String,
	pub command_line: String,
}

/// CPU information.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CpuInfo {
	pub model_name: String,
	pub cores_physical: u32,
	pub cores_logical: u32,
	pub frequency_mhz: f64,
	pub cache_size_kb: u64,
	pub load_average: [f64; 3],
	pub usage_percent: f64,
}
