//! Policy engine -- access control for Mycelium tools.

pub mod capability;
#[cfg(feature = "toml")]
pub mod config;
pub mod profile;
pub mod rule;

use std::collections::HashMap;

use profile::Profile;
use rule::{Action, PolicyRule, ResourceContext, tool_category};

pub use capability::Capability;
pub use profile::Role;
pub use rule::ResourceFilter;

/// Per-tool rate limit configuration.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RateLimit {
	/// Maximum number of calls allowed within the window.
	pub max_calls: u32,
	/// Window duration in seconds.
	pub window_secs: u64,
}

/// Top-level policy configuration.
#[derive(Debug, Clone)]
pub struct Policy {
	pub global_rules: Vec<PolicyRule>,
	pub profiles: Vec<Profile>,
	pub default_profile: String,
	pub dry_run: bool,
	/// Per-tool rate limits for destructive operations.
	pub rate_limits: HashMap<String, RateLimit>,
}

impl Default for Policy {
	fn default() -> Self {
		Self {
			global_rules: vec![PolicyRule {
				action: Action::Allow,
				target: rule::RuleTarget::All,
				filter: None,
				reason: Some("default: allow all".into()),
			}],
			profiles: vec![],
			default_profile: "default".into(),
			dry_run: false,
			rate_limits: HashMap::new(),
		}
	}
}

impl Policy {
	/// Resolve a profile by name. Falls back to default_profile, then to
	/// a synthesized admin profile if nothing matches.
	pub fn resolve_profile(&self, name: &str) -> Option<&Profile> {
		self.profiles.iter().find(|p| p.name == name).or_else(|| {
			self.profiles
				.iter()
				.find(|p| p.name == self.default_profile)
		})
	}

	/// Build an effective policy for a given agent/profile name.
	pub fn effective(&self, profile_name: &str) -> EffectivePolicy {
		let profile = self.resolve_profile(profile_name);

		let mut rules = self.global_rules.clone();
		let dry_run;

		if let Some(prof) = profile {
			rules.extend(prof.effective_rules());
			dry_run = self.dry_run || prof.dry_run;
		} else {
			dry_run = self.dry_run;
		}

		EffectivePolicy { rules, dry_run }
	}

	/// List all profile names.
	pub fn profile_names(&self) -> Vec<&str> {
		self.profiles.iter().map(|p| p.name.as_str()).collect()
	}
}

/// The merged, ready-to-evaluate policy for a single agent session.
#[derive(Debug, Clone)]
pub struct EffectivePolicy {
	rules: Vec<PolicyRule>,
	dry_run: bool,
}

/// Result of a policy evaluation.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
	pub allowed: bool,
	pub dry_run: bool,
	pub reason: Option<String>,
}

impl EffectivePolicy {
	/// Evaluate whether a tool call is permitted.
	///
	/// Rules are scanned in order. Among matching rules, the most specific
	/// target wins. At equal specificity, the last matching rule wins.
	/// This allows profile rules (appended after global rules) to override
	/// global defaults.
	pub fn evaluate(&self, tool_name: &str, resource: Option<&ResourceContext>) -> PolicyDecision {
		let category = tool_category(tool_name);
		let mut best_specificity: Option<u8> = None;
		let mut best_action = Action::Deny;
		let mut best_reason: Option<String> = None;

		for rule in &self.rules {
			if let Some(specificity) = rule.matches(tool_name, category, resource) {
				let dominated = best_specificity.is_some_and(|best| specificity < best);
				if dominated {
					continue;
				}

				// At same or higher specificity, last match wins.
				// Profile rules come after global rules, so they override.
				best_specificity = Some(specificity);
				best_action = rule.action;
				best_reason = rule.reason.clone();
			}
		}

		PolicyDecision {
			allowed: best_action == Action::Allow,
			dry_run: self.dry_run,
			reason: best_reason,
		}
	}

	/// Whether this policy forces dry-run mode.
	pub fn is_dry_run(&self) -> bool {
		self.dry_run
	}

	/// Get the raw rules (for display/debugging).
	pub fn rules(&self) -> &[PolicyRule] {
		&self.rules
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use profile::Profile;
	use rule::{Action, PolicyRule, RuleTarget};

	/// Helper: build a Policy from parts, filling in rate_limits as empty.
	fn policy(
		global_rules: Vec<PolicyRule>,
		profiles: Vec<Profile>,
		default_profile: &str,
		dry_run: bool,
	) -> Policy {
		Policy {
			global_rules,
			profiles,
			default_profile: default_profile.into(),
			dry_run,
			rate_limits: HashMap::new(),
		}
	}

	fn allow_all() -> PolicyRule {
		PolicyRule {
			action: Action::Allow,
			target: RuleTarget::All,
			filter: None,
			reason: None,
		}
	}

	fn deny_capability(cap: Capability) -> PolicyRule {
		PolicyRule {
			action: Action::Deny,
			target: RuleTarget::Capability(cap),
			filter: None,
			reason: Some(format!("deny {cap}")),
		}
	}

	fn allow_tool(name: &str) -> PolicyRule {
		PolicyRule {
			action: Action::Allow,
			target: RuleTarget::Tool(name.into()),
			filter: None,
			reason: None,
		}
	}

	#[test]
	fn default_policy_allows_everything() {
		let policy = Policy::default();
		let effective = policy.effective("nonexistent");
		let decision = effective.evaluate("process_list", None);
		assert!(decision.allowed);
	}

	#[test]
	fn read_only_denies_writes() {
		let p = policy(
			vec![],
			vec![Profile {
				name: "readonly-bot".into(),
				role: Role::ReadOnly,
				rules: vec![],
				dry_run: false,
			}],
			"readonly-bot",
			false,
		);

		let effective = p.effective("readonly-bot");

		// Reads should be allowed
		assert!(effective.evaluate("process_list", None).allowed);
		assert!(effective.evaluate("memory_info", None).allowed);
		assert!(effective.evaluate("network_interfaces", None).allowed);

		// Writes should be denied
		assert!(!effective.evaluate("process_kill", None).allowed);
		assert!(!effective.evaluate("tuning_set", None).allowed);
		assert!(!effective.evaluate("service_action", None).allowed);
		assert!(!effective.evaluate("firewall_add", None).allowed);
		assert!(!effective.evaluate("probe_attach", None).allowed);
	}

	#[test]
	fn operator_allows_service_and_process_management() {
		let p = policy(
			vec![],
			vec![Profile {
				name: "ops".into(),
				role: Role::Operator,
				rules: vec![],
				dry_run: false,
			}],
			"ops",
			false,
		);
		let effective = p.effective("ops");
		assert!(effective.evaluate("process_list", None).allowed);
		assert!(effective.evaluate("process_kill", None).allowed);
		assert!(effective.evaluate("service_action", None).allowed);
		assert!(!effective.evaluate("tuning_set", None).allowed);
		assert!(!effective.evaluate("firewall_add", None).allowed);
		assert!(!effective.evaluate("probe_attach", None).allowed);
	}

	#[test]
	fn admin_allows_everything() {
		let p = policy(
			vec![],
			vec![Profile {
				name: "admin".into(),
				role: Role::Admin,
				rules: vec![],
				dry_run: false,
			}],
			"admin",
			false,
		);
		let effective = p.effective("admin");
		assert!(effective.evaluate("process_kill", None).allowed);
		assert!(effective.evaluate("tuning_set", None).allowed);
		assert!(effective.evaluate("firewall_add", None).allowed);
		assert!(effective.evaluate("probe_attach", None).allowed);
		assert!(effective.evaluate("policy_switch_profile", None).allowed);
	}

	#[test]
	fn profile_rules_override_role_preset() {
		let p = policy(
			vec![],
			vec![Profile {
				name: "special".into(),
				role: Role::ReadOnly,
				rules: vec![allow_tool("process_kill")],
				dry_run: false,
			}],
			"special",
			false,
		);
		let effective = p.effective("special");
		assert!(effective.evaluate("process_kill", None).allowed);
		assert!(!effective.evaluate("tuning_set", None).allowed);
	}

	#[test]
	fn resource_filter_on_service_names() {
		let p = policy(
			vec![allow_all()],
			vec![Profile {
				name: "limited".into(),
				role: Role::Custom,
				rules: vec![
					PolicyRule {
						action: Action::Allow,
						target: RuleTarget::Tool("service_action".into()),
						filter: Some(ResourceFilter::ServiceNames(vec![
							"nginx".into(),
							"redis".into(),
						])),
						reason: None,
					},
					PolicyRule {
						action: Action::Deny,
						target: RuleTarget::Tool("service_action".into()),
						filter: None,
						reason: Some("only nginx and redis allowed".into()),
					},
				],
				dry_run: false,
			}],
			"limited",
			false,
		);
		let effective = p.effective("limited");
		let ctx = ResourceContext {
			service_name: Some("nginx".into()),
			..Default::default()
		};
		assert!(effective.evaluate("service_action", Some(&ctx)).allowed);
		let ctx = ResourceContext {
			service_name: Some("postgresql".into()),
			..Default::default()
		};
		assert!(!effective.evaluate("service_action", Some(&ctx)).allowed);
	}

	#[test]
	fn resource_filter_on_tunable_prefixes() {
		let p = policy(
			vec![allow_all()],
			vec![Profile {
				name: "tuner".into(),
				role: Role::Custom,
				rules: vec![PolicyRule {
					action: Action::Deny,
					target: RuleTarget::Tool("tuning_set".into()),
					filter: Some(ResourceFilter::TunablePrefixes(vec!["kernel.".into()])),
					reason: Some("kernel namespace forbidden".into()),
				}],
				dry_run: false,
			}],
			"tuner",
			false,
		);
		let effective = p.effective("tuner");
		let ctx = ResourceContext {
			tunable_key: Some("net.ipv4.ip_forward".into()),
			..Default::default()
		};
		assert!(effective.evaluate("tuning_set", Some(&ctx)).allowed);
		let ctx = ResourceContext {
			tunable_key: Some("kernel.panic".into()),
			..Default::default()
		};
		assert!(!effective.evaluate("tuning_set", Some(&ctx)).allowed);
	}

	#[test]
	fn dry_run_propagates() {
		let p = policy(
			vec![allow_all()],
			vec![Profile {
				name: "careful".into(),
				role: Role::Admin,
				rules: vec![],
				dry_run: true,
			}],
			"careful",
			false,
		);
		let effective = p.effective("careful");
		assert!(effective.is_dry_run());
		let decision = effective.evaluate("process_kill", None);
		assert!(decision.allowed);
		assert!(decision.dry_run);
	}

	#[test]
	fn global_dry_run_overrides_profile() {
		let p = policy(
			vec![allow_all()],
			vec![Profile {
				name: "fast".into(),
				role: Role::Admin,
				rules: vec![],
				dry_run: false,
			}],
			"fast",
			true,
		);
		let effective = p.effective("fast");
		assert!(effective.is_dry_run());
	}

	#[test]
	fn unknown_profile_falls_back_to_default() {
		let p = policy(
			vec![],
			vec![Profile {
				name: "default".into(),
				role: Role::ReadOnly,
				rules: vec![],
				dry_run: false,
			}],
			"default",
			false,
		);
		let effective = p.effective("nonexistent-agent");
		assert!(!effective.evaluate("process_kill", None).allowed);
	}

	#[test]
	fn last_rule_wins_at_same_specificity() {
		let p = policy(
			vec![],
			vec![Profile {
				name: "test".into(),
				role: Role::Custom,
				rules: vec![
					allow_tool("process_kill"),
					PolicyRule {
						action: Action::Deny,
						target: RuleTarget::Tool("process_kill".into()),
						filter: None,
						reason: Some("explicitly denied".into()),
					},
				],
				dry_run: false,
			}],
			"test",
			false,
		);
		let effective = p.effective("test");
		assert!(!effective.evaluate("process_kill", None).allowed);

		let p2 = policy(
			vec![PolicyRule {
				action: Action::Deny,
				target: RuleTarget::Tool("process_kill".into()),
				filter: None,
				reason: None,
			}],
			vec![Profile {
				name: "override".into(),
				role: Role::Custom,
				rules: vec![allow_tool("process_kill")],
				dry_run: false,
			}],
			"override",
			false,
		);
		let effective2 = p2.effective("override");
		assert!(effective2.evaluate("process_kill", None).allowed);
	}

	#[test]
	fn more_specific_rule_wins() {
		let p = policy(
			vec![],
			vec![Profile {
				name: "test".into(),
				role: Role::Custom,
				rules: vec![
					PolicyRule {
						action: Action::Deny,
						target: RuleTarget::Category("process".into()),
						filter: None,
						reason: Some("deny all process tools".into()),
					},
					allow_tool("process_list"),
				],
				dry_run: false,
			}],
			"test",
			false,
		);
		let effective = p.effective("test");
		assert!(effective.evaluate("process_list", None).allowed);
		assert!(!effective.evaluate("process_kill", None).allowed);
	}

	#[test]
	fn global_rules_combine_with_profile() {
		let p = policy(
			vec![allow_all(), deny_capability(Capability::ProbeManage)],
			vec![Profile {
				name: "admin".into(),
				role: Role::Admin,
				rules: vec![],
				dry_run: false,
			}],
			"admin",
			false,
		);
		let effective = p.effective("admin");
		assert!(effective.evaluate("process_list", None).allowed);
	}
}
