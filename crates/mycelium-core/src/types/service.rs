//! Service management types.

/// Information about a system service.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ServiceInfo {
	pub name: String,
	pub display_name: String,
	pub state: ServiceState,
	pub enabled: bool,
	pub pid: Option<u32>,
	pub description: Option<String>,
}

/// Service runtime state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ServiceState {
	Running,
	Stopped,
	Failed,
	Reloading,
	Activating,
	Deactivating,
	Unknown,
}

/// Action to perform on a service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ServiceAction {
	Start,
	Stop,
	Restart,
	Reload,
	Enable,
	Disable,
}
