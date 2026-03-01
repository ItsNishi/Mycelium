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
