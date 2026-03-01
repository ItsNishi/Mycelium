//! eBPF probe types (Linux only, feature-gated).

/// Handle to an attached probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ProbeHandle(pub u64);

/// Configuration for attaching a probe.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ProbeConfig {
	pub probe_type: ProbeType,
	pub target: Option<String>,
	pub filter: Option<String>,
}

/// Kind of eBPF probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ProbeType {
	SyscallTrace,
	NetworkMonitor,
}

/// Information about an active probe.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ProbeInfo {
	pub handle: ProbeHandle,
	pub probe_type: ProbeType,
	pub target: Option<String>,
	pub events_captured: u64,
}

/// A single event captured by a probe.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ProbeEvent {
	pub timestamp: u64,
	pub pid: u32,
	pub process_name: String,
	pub event_type: String,
	pub details: String,
}
