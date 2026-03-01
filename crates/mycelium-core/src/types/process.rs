//! Process-related types.

/// Information about a running process.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ProcessInfo {
	pub pid: u32,
	pub ppid: u32,
	pub name: String,
	pub state: ProcessState,
	pub user: String,
	pub uid: u32,
	pub threads: u32,
	pub cpu_percent: f64,
	pub memory_bytes: u64,
	pub command: String,
	pub start_time: u64,
}

/// Process state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ProcessState {
	Running,
	Sleeping,
	DiskSleep,
	Stopped,
	Zombie,
	Dead,
	Unknown,
}

/// Resource usage for a single process.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ProcessResource {
	pub pid: u32,
	pub cpu_percent: f64,
	pub memory_bytes: u64,
	pub memory_percent: f64,
	pub virtual_memory_bytes: u64,
	pub open_fds: u32,
	pub threads: u32,
	pub read_bytes: u64,
	pub write_bytes: u64,
}

/// Memory details for a single process.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ProcessMemory {
	pub pid: u32,
	pub rss_bytes: u64,
	pub virtual_bytes: u64,
	pub shared_bytes: u64,
	pub text_bytes: u64,
	pub data_bytes: u64,
}

/// Signal to send to a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Signal {
	Term,
	Kill,
	Hup,
	Int,
	Usr1,
	Usr2,
	Stop,
	Cont,
}
