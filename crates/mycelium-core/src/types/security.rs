//! Security-related types.

/// A system user account.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UserInfo {
	pub name: String,
	pub uid: u32,
	pub gid: u32,
	pub home: String,
	pub shell: String,
	pub groups: Vec<String>,
}

/// A system group.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GroupInfo {
	pub name: String,
	pub gid: u32,
	pub members: Vec<String>,
}

/// A loaded kernel module.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KernelModule {
	pub name: String,
	pub size_bytes: u64,
	pub used_by: Vec<String>,
	pub state: ModuleState,
}

/// Kernel module state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ModuleState {
	Live,
	Loading,
	Unloading,
	Unknown,
}

/// Overall security status of the system.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SecurityStatus {
	pub selinux: Option<LsmStatus>,
	pub apparmor: Option<LsmStatus>,
	pub firewall_active: bool,
	pub root_login_allowed: bool,
	pub password_auth_ssh: bool,
}

/// Linux Security Module status.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LsmStatus {
	pub enabled: bool,
	pub mode: String,
}

/// The type of persistence mechanism found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PersistenceType {
	// Windows
	RegistryRun,
	ScheduledTask,
	Service,
	StartupFolder,
	WmiSubscription,
	ComHijack,
	// Linux
	CronJob,
	SystemdTimer,
	InitScript,
	XdgAutostart,
	ShellProfile,
	UdevRule,
}

/// A discovered persistence entry.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PersistenceEntry {
	pub persistence_type: PersistenceType,
	pub name: String,
	pub location: String,
	pub value: String,
	pub enabled: bool,
	pub description: Option<String>,
}

/// The type of API hook detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum HookType {
	// Windows
	InlineHook,
	IatHook,
	EatHook,
	// Linux
	LdPreload,
	GotPltHook,
	PtraceAttach,
}

/// A detected API hook.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HookInfo {
	pub hook_type: HookType,
	pub module: String,
	pub function: String,
	pub address: u64,
	pub expected_bytes: Vec<u8>,
	pub actual_bytes: Vec<u8>,
	pub destination: Option<u64>,
	pub destination_module: Option<String>,
}
