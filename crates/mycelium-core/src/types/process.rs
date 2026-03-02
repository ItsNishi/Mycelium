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

/// Information about a single thread within a process.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ThreadInfo {
	pub tid: u32,
	pub pid: u32,
	pub priority: i32,
}

/// A loaded module (DLL / shared library) within a process.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ProcessModule {
	pub name: String,
	pub path: String,
	pub base_address: u64,
	pub size: u64,
}

/// A privilege held by a process token.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PrivilegeInfo {
	pub name: String,
	pub enabled: bool,
}

/// An open handle held by a process.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HandleInfo {
	pub handle_value: u64,
	pub object_type: String,
	pub name: Option<String>,
	pub access_mask: u32,
}

/// Target for PE header inspection.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PeTarget {
	Pid(u32),
	Path(String),
}

/// Parsed PE header information.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PeInfo {
	pub machine: String,
	pub characteristics: Vec<String>,
	pub entry_point: u64,
	pub image_base: u64,
	pub image_size: u32,
	pub timestamp: u64,
	pub subsystem: String,
	pub sections: Vec<PeSection>,
	pub imports: Vec<PeImport>,
	pub exports: Vec<PeExport>,
}

/// A PE section header.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PeSection {
	pub name: String,
	pub virtual_address: u64,
	pub virtual_size: u32,
	pub raw_size: u32,
	pub characteristics: Vec<String>,
}

/// A PE import entry (DLL + imported functions).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PeImport {
	pub dll_name: String,
	pub functions: Vec<String>,
}

/// A PE export entry.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PeExport {
	pub ordinal: u16,
	pub name: Option<String>,
	pub rva: u32,
}

/// Extended token security details for a process.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TokenInfo {
	pub pid: u32,
	pub user: String,
	pub integrity_level: String,
	pub token_type: String,
	pub impersonation_level: Option<String>,
	pub elevation_type: String,
	pub is_elevated: bool,
	pub is_restricted: bool,
	pub session_id: u32,
	pub groups: Vec<TokenGroup>,
	pub privileges: Vec<PrivilegeInfo>,
}

/// A group entry from a process token.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TokenGroup {
	pub name: String,
	pub sid: String,
	pub attributes: Vec<String>,
}
