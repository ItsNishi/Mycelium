//! Capability flags used by policy rules to group related operations.

/// A logical capability that one or more MCP tools require.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Capability {
	/// Kill / signal processes.
	ProcessManage,
	/// Modify kernel tunables (sysctl).
	KernelTune,
	/// Add / remove firewall rules.
	FirewallManage,
	/// Start / stop / restart services.
	ServiceManage,
	/// Attach / detach eBPF probes.
	ProbeManage,
	/// Switch active policy profile at runtime.
	PolicyManage,
}

impl Capability {
	/// Tools that require this capability.
	pub fn tools(&self) -> &[&str] {
		match self {
			Self::ProcessManage => &["process_kill"],
			Self::KernelTune => &["tuning_set"],
			Self::FirewallManage => &["firewall_add", "firewall_remove"],
			Self::ServiceManage => &["service_action"],
			Self::ProbeManage => &["probe_attach", "probe_detach"],
			Self::PolicyManage => &["policy_switch_profile"],
		}
	}

	/// Whether a given tool name falls under this capability.
	pub fn covers_tool(&self, tool: &str) -> bool {
		self.tools().contains(&tool)
	}
}

impl std::fmt::Display for Capability {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let s = match self {
			Self::ProcessManage => "process_manage",
			Self::KernelTune => "kernel_tune",
			Self::FirewallManage => "firewall_manage",
			Self::ServiceManage => "service_manage",
			Self::ProbeManage => "probe_manage",
			Self::PolicyManage => "policy_manage",
		};
		write!(f, "{s}")
	}
}

impl std::str::FromStr for Capability {
	type Err = String;

	fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
		match s {
			"process_manage" => Ok(Self::ProcessManage),
			"kernel_tune" => Ok(Self::KernelTune),
			"firewall_manage" => Ok(Self::FirewallManage),
			"service_manage" => Ok(Self::ServiceManage),
			"probe_manage" => Ok(Self::ProbeManage),
			"policy_manage" => Ok(Self::PolicyManage),
			_ => Err(format!("unknown capability: {s}")),
		}
	}
}
