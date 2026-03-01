/// Storage-related types.

/// Physical disk information.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DiskInfo {
	pub name: String,
	pub model: Option<String>,
	pub serial: Option<String>,
	pub size_bytes: u64,
	pub removable: bool,
	pub rotational: bool,
}

/// A disk partition.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Partition {
	pub name: String,
	pub parent_disk: String,
	pub size_bytes: u64,
	pub filesystem: Option<String>,
	pub mount_point: Option<String>,
	pub label: Option<String>,
	pub uuid: Option<String>,
}

/// A mounted filesystem.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MountPoint {
	pub device: String,
	pub mount_path: String,
	pub filesystem: String,
	pub options: String,
	pub total_bytes: u64,
	pub used_bytes: u64,
	pub available_bytes: u64,
	pub use_percent: f64,
}

/// I/O statistics for a block device.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IoStats {
	pub device: String,
	pub reads_completed: u64,
	pub writes_completed: u64,
	pub read_bytes: u64,
	pub write_bytes: u64,
	pub io_in_progress: u64,
	pub io_time_ms: u64,
}
