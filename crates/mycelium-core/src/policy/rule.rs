/// Policy rule types.

use super::capability::Capability;

/// A single policy rule that allows or denies access.
#[derive(Debug, Clone)]
pub struct PolicyRule {
	pub action: Action,
	pub target: RuleTarget,
	pub filter: Option<ResourceFilter>,
	pub reason: Option<String>,
}

/// Whether the rule allows or denies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
	Allow,
	Deny,
}

/// What the rule applies to.
#[derive(Debug, Clone)]
pub enum RuleTarget {
	/// A specific MCP tool name (e.g. "process_kill").
	Tool(String),
	/// All tools in a category (e.g. "process", "network").
	Category(String),
	/// A capability group.
	Capability(Capability),
	/// All tools.
	All,
}

impl RuleTarget {
	/// Base specificity level for conflict resolution (higher = more specific).
	/// Filtered rules get +4 bonus via `PolicyRule::matches`.
	fn base_specificity(&self) -> u8 {
		match self {
			Self::All => 0,
			Self::Capability(_) => 1,
			Self::Category(_) => 2,
			Self::Tool(_) => 3,
		}
	}
}

/// Optional fine-grained filter on what resources a rule applies to.
#[derive(Debug, Clone)]
pub enum ResourceFilter {
	/// Allow/deny only for these service names.
	ServiceNames(Vec<String>),
	/// Allow/deny only for sysctl keys with these prefixes.
	TunablePrefixes(Vec<String>),
	/// Allow/deny only for processes owned by these users.
	ProcessOwners(Vec<String>),
	/// Allow/deny only for PIDs in this range.
	PidRange { min: u32, max: u32 },
	/// Allow/deny only for these network interfaces.
	InterfaceNames(Vec<String>),
	/// Allow/deny only for these log sources.
	LogSources(Vec<String>),
}

/// Context about the resource being accessed, used for filter matching.
#[derive(Debug, Clone, Default)]
pub struct ResourceContext {
	pub service_name: Option<String>,
	pub tunable_key: Option<String>,
	pub pid: Option<u32>,
	pub process_owner: Option<String>,
	pub interface_name: Option<String>,
	pub log_source: Option<String>,
}

/// Extract the category from a tool name (everything before the first `_`).
pub fn tool_category(tool: &str) -> &str {
	tool.split('_').next().unwrap_or(tool)
}

impl PolicyRule {
	/// Check if this rule matches the given tool and optional resource context.
	/// Returns `(matches, specificity)`.
	pub fn matches(
		&self,
		tool_name: &str,
		category: &str,
		resource: Option<&ResourceContext>,
	) -> Option<u8> {
		let target_matches = match &self.target {
			RuleTarget::All => true,
			RuleTarget::Tool(t) => t == tool_name,
			RuleTarget::Category(c) => c == category,
			RuleTarget::Capability(cap) => cap.covers_tool(tool_name),
		};

		if !target_matches {
			return None;
		}

		// If there's a resource filter, check it.
		// A matching filter adds a specificity bonus so filtered rules
		// take priority over unfiltered rules at the same target level.
		let filter_bonus: u8 = if let Some(filter) = &self.filter {
			if !Self::filter_matches(filter, resource) {
				return None;
			}
			4
		} else {
			0
		};

		Some(self.target.base_specificity() + filter_bonus)
	}

	fn filter_matches(filter: &ResourceFilter, resource: Option<&ResourceContext>) -> bool {
		let Some(ctx) = resource else {
			// No context provided -- filter cannot match
			return false;
		};

		match filter {
			ResourceFilter::ServiceNames(names) => ctx
				.service_name
				.as_ref()
				.is_some_and(|s| names.iter().any(|n| n == s)),
			ResourceFilter::TunablePrefixes(prefixes) => ctx
				.tunable_key
				.as_ref()
				.is_some_and(|k| prefixes.iter().any(|p| k.starts_with(p))),
			ResourceFilter::ProcessOwners(owners) => ctx
				.process_owner
				.as_ref()
				.is_some_and(|o| owners.iter().any(|own| own == o)),
			ResourceFilter::PidRange { min, max } => {
				ctx.pid.is_some_and(|p| p >= *min && p <= *max)
			}
			ResourceFilter::InterfaceNames(names) => ctx
				.interface_name
				.as_ref()
				.is_some_and(|i| names.iter().any(|n| n == i)),
			ResourceFilter::LogSources(sources) => ctx
				.log_source
				.as_ref()
				.is_some_and(|s| sources.iter().any(|src| src == s)),
		}
	}
}
