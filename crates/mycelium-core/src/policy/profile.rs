//! Profile and role preset definitions.

use super::capability::Capability;
use super::rule::{Action, PolicyRule, RuleTarget};

/// Base role presets that expand to default rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
	/// All read tools allowed, all write tools denied.
	ReadOnly,
	/// Reads + service/process management. No kernel tuning, firewall, or probes.
	Operator,
	/// Everything allowed.
	Admin,
	/// No preset rules -- fully user-defined.
	Custom,
}

impl Role {
	/// Expand this role into its preset rules.
	pub fn preset_rules(&self) -> Vec<PolicyRule> {
		match self {
			Self::ReadOnly => vec![
				PolicyRule {
					action: Action::Allow,
					target: RuleTarget::All,
					filter: None,
					reason: Some("read-only: allow all reads".into()),
				},
				PolicyRule {
					action: Action::Deny,
					target: RuleTarget::Capability(Capability::ProcessManage),
					filter: None,
					reason: Some("read-only: no process management".into()),
				},
				PolicyRule {
					action: Action::Deny,
					target: RuleTarget::Capability(Capability::KernelTune),
					filter: None,
					reason: Some("read-only: no kernel tuning".into()),
				},
				PolicyRule {
					action: Action::Deny,
					target: RuleTarget::Capability(Capability::FirewallManage),
					filter: None,
					reason: Some("read-only: no firewall management".into()),
				},
				PolicyRule {
					action: Action::Deny,
					target: RuleTarget::Capability(Capability::ServiceManage),
					filter: None,
					reason: Some("read-only: no service management".into()),
				},
				PolicyRule {
					action: Action::Deny,
					target: RuleTarget::Capability(Capability::ProbeManage),
					filter: None,
					reason: Some("read-only: no probe management".into()),
				},
				PolicyRule {
					action: Action::Deny,
					target: RuleTarget::Capability(Capability::PolicyManage),
					filter: None,
					reason: Some("read-only: no policy management".into()),
				},
				PolicyRule {
					action: Action::Deny,
					target: RuleTarget::Capability(Capability::MemoryAccess),
					filter: None,
					reason: Some("read-only: no direct memory access".into()),
				},
			],
			Self::Operator => vec![
				PolicyRule {
					action: Action::Allow,
					target: RuleTarget::All,
					filter: None,
					reason: Some("operator: allow most operations".into()),
				},
				PolicyRule {
					action: Action::Deny,
					target: RuleTarget::Capability(Capability::KernelTune),
					filter: None,
					reason: Some("operator: no kernel tuning".into()),
				},
				PolicyRule {
					action: Action::Deny,
					target: RuleTarget::Capability(Capability::FirewallManage),
					filter: None,
					reason: Some("operator: no firewall management".into()),
				},
				PolicyRule {
					action: Action::Deny,
					target: RuleTarget::Capability(Capability::ProbeManage),
					filter: None,
					reason: Some("operator: no probe management".into()),
				},
				PolicyRule {
					action: Action::Deny,
					target: RuleTarget::Capability(Capability::PolicyManage),
					filter: None,
					reason: Some("operator: no policy management".into()),
				},
				PolicyRule {
					action: Action::Deny,
					target: RuleTarget::Capability(Capability::MemoryAccess),
					filter: None,
					reason: Some("operator: no direct memory access".into()),
				},
			],
			Self::Admin => vec![PolicyRule {
				action: Action::Allow,
				target: RuleTarget::All,
				filter: None,
				reason: Some("admin: full access".into()),
			}],
			Self::Custom => vec![],
		}
	}
}

impl std::fmt::Display for Role {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let s = match self {
			Self::ReadOnly => "read-only",
			Self::Operator => "operator",
			Self::Admin => "admin",
			Self::Custom => "custom",
		};
		write!(f, "{s}")
	}
}

impl std::str::FromStr for Role {
	type Err = String;

	fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
		match s {
			"read-only" | "readonly" => Ok(Self::ReadOnly),
			"operator" => Ok(Self::Operator),
			"admin" => Ok(Self::Admin),
			"custom" => Ok(Self::Custom),
			_ => Err(format!("unknown role: {s}")),
		}
	}
}

/// A named profile that combines a role preset with additional rules.
#[derive(Debug, Clone)]
pub struct Profile {
	pub name: String,
	pub role: Role,
	pub rules: Vec<PolicyRule>,
	pub dry_run: bool,
}

impl Profile {
	/// Build the effective rule list: role preset + profile overrides.
	pub fn effective_rules(&self) -> Vec<PolicyRule> {
		let mut rules = self.role.preset_rules();
		rules.extend(self.rules.iter().cloned());
		rules
	}
}
