use clap::Subcommand;
use mycelium_core::policy::{Policy, Role};
use mycelium_core::policy::profile::Profile;
use mycelium_core::policy::rule::{Action, PolicyRule, RuleTarget, ResourceFilter};
use mycelium_core::policy::capability::Capability;

use crate::output::OutputFormat;

#[derive(Subcommand)]
pub enum PolicyCmd {
	/// Show effective policy for a profile
	Show {
		/// Profile name
		#[arg(long, default_value = "default")]
		profile: String,

		/// Path to policy TOML file
		#[arg(long)]
		config: Option<String>,
	},
	/// List all available profiles
	List {
		/// Path to policy TOML file
		#[arg(long)]
		config: Option<String>,
	},
	/// Validate a policy TOML file
	Validate {
		/// Path to TOML file
		path: String,
	},
}

impl PolicyCmd {
	pub fn run(&self, format: OutputFormat) {
		match self {
			Self::Show { profile, config } => {
				let policy = load_policy(config.as_deref());
				let effective = policy.effective(profile);

				if format == OutputFormat::Json {
					// Serialize rules as JSON
					let rules: Vec<RuleDisplay> = effective
						.rules()
						.iter()
						.map(RuleDisplay::from)
						.collect();
					match serde_json::to_string_pretty(&rules) {
						Ok(json) => println!("{json}"),
						Err(e) => eprintln!("error: {e}"),
					}
				} else {
					println!("Effective policy for profile: {profile}");
					println!("Dry-run: {}", effective.is_dry_run());
					println!();
					println!(
						"{:<8} {:<30} {}",
						"ACTION", "TARGET", "REASON"
					);
					for rule in effective.rules() {
						let action = match rule.action {
							Action::Allow => "ALLOW",
							Action::Deny => "DENY",
						};
						let target = format_target(&rule.target);
						let reason = rule.reason.as_deref().unwrap_or("-");
						println!("{:<8} {:<30} {}", action, target, reason);
					}
				}
			}
			Self::List { config } => {
				let policy = load_policy(config.as_deref());
				let names = policy.profile_names();

				if format == OutputFormat::Json {
					match serde_json::to_string_pretty(&names) {
						Ok(json) => println!("{json}"),
						Err(e) => eprintln!("error: {e}"),
					}
				} else {
					println!("Default profile: {}", policy.default_profile);
					println!();
					for name in &names {
						let profile = policy
							.profiles
							.iter()
							.find(|p| p.name == *name)
							.unwrap();
						println!(
							"  {:<20} role={:<12} dry_run={} rules={}",
							name,
							profile.role.to_string(),
							profile.dry_run,
							profile.rules.len(),
						);
					}
				}
			}
			Self::Validate { path } => {
				match std::fs::read_to_string(path) {
					Ok(content) => match parse_policy_toml(&content) {
						Ok(policy) => {
							println!("Policy file is valid.");
							println!(
								"  Profiles: {}",
								policy.profile_names().join(", ")
							);
							println!(
								"  Default: {}",
								policy.default_profile
							);
							println!(
								"  Global rules: {}",
								policy.global_rules.len()
							);
						}
						Err(e) => {
							eprintln!("Invalid policy file: {e}");
							std::process::exit(1);
						}
					},
					Err(e) => {
						eprintln!("Cannot read {path}: {e}");
						std::process::exit(1);
					}
				}
			}
		}
	}
}

fn format_target(target: &RuleTarget) -> String {
	match target {
		RuleTarget::All => "all".into(),
		RuleTarget::Tool(t) => format!("tool:{t}"),
		RuleTarget::Category(c) => format!("category:{c}"),
		RuleTarget::Capability(cap) => format!("capability:{cap}"),
	}
}

#[derive(serde::Serialize)]
struct RuleDisplay {
	action: String,
	target: String,
	filter: Option<String>,
	reason: Option<String>,
}

impl From<&PolicyRule> for RuleDisplay {
	fn from(rule: &PolicyRule) -> Self {
		Self {
			action: match rule.action {
				Action::Allow => "allow".into(),
				Action::Deny => "deny".into(),
			},
			target: format_target(&rule.target),
			filter: rule.filter.as_ref().map(|f| format!("{f:?}")),
			reason: rule.reason.clone(),
		}
	}
}

/// Load policy from TOML file or return default.
fn load_policy(config_path: Option<&str>) -> Policy {
	let path = config_path
		.map(|p| p.to_string())
		.or_else(|| {
			dirs_path("mycelium/policy.toml")
		});

	match path {
		Some(p) => match std::fs::read_to_string(&p) {
			Ok(content) => match parse_policy_toml(&content) {
				Ok(policy) => policy,
				Err(e) => {
					eprintln!("warning: failed to parse {p}: {e}");
					Policy::default()
				}
			},
			Err(_) => Policy::default(),
		},
		None => Policy::default(),
	}
}

fn dirs_path(relative: &str) -> Option<String> {
	let config_dir = std::env::var("XDG_CONFIG_HOME")
		.ok()
		.unwrap_or_else(|| {
			let home = std::env::var("HOME").unwrap_or_default();
			format!("{home}/.config")
		});
	let path = format!("{config_dir}/{relative}");
	Some(path)
}

/// Parse a TOML string into a Policy.
pub fn parse_policy_toml(content: &str) -> Result<Policy, String> {
	let table: toml::Value = content.parse().map_err(|e| format!("TOML parse error: {e}"))?;

	let global = table.get("global");

	let default_profile = global
		.and_then(|g| g.get("default_profile"))
		.and_then(|v| v.as_str())
		.unwrap_or("default")
		.to_string();

	let dry_run = global
		.and_then(|g| g.get("dry_run"))
		.and_then(|v| v.as_bool())
		.unwrap_or(false);

	let global_rules = global
		.and_then(|g| g.get("rules"))
		.and_then(|v| v.as_array())
		.map(|arr| {
			arr.iter()
				.filter_map(|v| parse_rule(v))
				.collect()
		})
		.unwrap_or_default();

	let profiles_table = table.get("profiles");
	let mut profiles = Vec::new();

	if let Some(toml::Value::Table(map)) = profiles_table {
		for (name, val) in map {
			if let Some(profile) = parse_profile(name, val) {
				profiles.push(profile);
			}
		}
	}

	Ok(Policy {
		global_rules,
		profiles,
		default_profile,
		dry_run,
	})
}

fn parse_rule(val: &toml::Value) -> Option<PolicyRule> {
	let action = match val.get("action")?.as_str()? {
		"allow" => Action::Allow,
		"deny" => Action::Deny,
		_ => return None,
	};

	let target = parse_target(val.get("target")?)?;
	let filter = val.get("filter").and_then(parse_filter);
	let reason = val
		.get("reason")
		.and_then(|v| v.as_str())
		.map(|s| s.to_string());

	Some(PolicyRule {
		action,
		target,
		filter,
		reason,
	})
}

fn parse_target(val: &toml::Value) -> Option<RuleTarget> {
	match val {
		toml::Value::String(s) if s == "all" => Some(RuleTarget::All),
		toml::Value::Table(map) => {
			if let Some(tool) = map.get("tool").and_then(|v| v.as_str()) {
				Some(RuleTarget::Tool(tool.to_string()))
			} else if let Some(cat) = map.get("category").and_then(|v| v.as_str()) {
				Some(RuleTarget::Category(cat.to_string()))
			} else if let Some(cap) = map.get("capability").and_then(|v| v.as_str()) {
				let capability: Capability = cap.parse().ok()?;
				Some(RuleTarget::Capability(capability))
			} else {
				None
			}
		}
		_ => None,
	}
}

fn parse_filter(val: &toml::Value) -> Option<ResourceFilter> {
	let map = val.as_table()?;

	if let Some(names) = map.get("service_names").and_then(|v| v.as_array()) {
		let names: Vec<String> = names
			.iter()
			.filter_map(|v| v.as_str().map(|s| s.to_string()))
			.collect();
		return Some(ResourceFilter::ServiceNames(names));
	}

	if let Some(prefixes) = map.get("tunable_prefixes").and_then(|v| v.as_array()) {
		let prefixes: Vec<String> = prefixes
			.iter()
			.filter_map(|v| v.as_str().map(|s| s.to_string()))
			.collect();
		return Some(ResourceFilter::TunablePrefixes(prefixes));
	}

	if let Some(owners) = map.get("process_owners").and_then(|v| v.as_array()) {
		let owners: Vec<String> = owners
			.iter()
			.filter_map(|v| v.as_str().map(|s| s.to_string()))
			.collect();
		return Some(ResourceFilter::ProcessOwners(owners));
	}

	if let Some(names) = map.get("interface_names").and_then(|v| v.as_array()) {
		let names: Vec<String> = names
			.iter()
			.filter_map(|v| v.as_str().map(|s| s.to_string()))
			.collect();
		return Some(ResourceFilter::InterfaceNames(names));
	}

	if let Some(sources) = map.get("log_sources").and_then(|v| v.as_array()) {
		let sources: Vec<String> = sources
			.iter()
			.filter_map(|v| v.as_str().map(|s| s.to_string()))
			.collect();
		return Some(ResourceFilter::LogSources(sources));
	}

	None
}

fn parse_profile(name: &str, val: &toml::Value) -> Option<Profile> {
	let role_str = val.get("role").and_then(|v| v.as_str()).unwrap_or("custom");
	let role: Role = role_str.parse().ok()?;

	let dry_run = val
		.get("dry_run")
		.and_then(|v| v.as_bool())
		.unwrap_or(false);

	let rules = val
		.get("rules")
		.and_then(|v| v.as_array())
		.map(|arr| arr.iter().filter_map(|v| parse_rule(v)).collect())
		.unwrap_or_default();

	Some(Profile {
		name: name.to_string(),
		role,
		rules,
		dry_run,
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	const SAMPLE_POLICY: &str = r#"
[global]
default_profile = "operator"
dry_run = false

[[global.rules]]
action = "allow"
target = "all"

[[global.rules]]
action = "deny"
target = { capability = "probe_manage" }
reason = "eBPF probes disabled globally"

[[global.rules]]
action = "deny"
target = { tool = "tuning_set" }
filter = { tunable_prefixes = ["kernel."] }
reason = "Kernel namespace tunables are dangerous"

[profiles.claude-code]
role = "admin"
dry_run = false

[[profiles.claude-code.rules]]
action = "allow"
target = { capability = "probe_manage" }

[profiles.openclaw]
role = "operator"

[[profiles.openclaw.rules]]
action = "allow"
target = { tool = "service_action" }
filter = { service_names = ["nginx", "postgresql", "redis"] }

[[profiles.openclaw.rules]]
action = "deny"
target = { tool = "service_action" }
reason = "OpenClaw can only manage nginx, postgresql, redis"

[profiles.restricted-bot]
role = "read-only"
dry_run = true
"#;

	#[test]
	fn parse_sample_policy() {
		let policy = parse_policy_toml(SAMPLE_POLICY).unwrap();

		assert_eq!(policy.default_profile, "operator");
		assert!(!policy.dry_run);
		assert_eq!(policy.global_rules.len(), 3);
		assert_eq!(policy.profiles.len(), 3);

		let names: Vec<&str> = policy.profile_names().into_iter().collect();
		assert!(names.contains(&"claude-code"));
		assert!(names.contains(&"openclaw"));
		assert!(names.contains(&"restricted-bot"));
	}

	#[test]
	fn admin_profile_overrides_global_probe_deny() {
		let policy = parse_policy_toml(SAMPLE_POLICY).unwrap();
		let effective = policy.effective("claude-code");

		// Admin with explicit probe_manage allow should override global deny
		assert!(effective.evaluate("probe_attach", None).allowed);
		assert!(effective.evaluate("process_kill", None).allowed);
	}

	#[test]
	fn restricted_bot_is_read_only_dry_run() {
		let policy = parse_policy_toml(SAMPLE_POLICY).unwrap();
		let effective = policy.effective("restricted-bot");

		assert!(effective.is_dry_run());
		assert!(!effective.evaluate("process_kill", None).allowed);
		assert!(!effective.evaluate("tuning_set", None).allowed);
		assert!(effective.evaluate("process_list", None).allowed);
	}

	#[test]
	fn openclaw_service_filter() {
		use mycelium_core::policy::rule::ResourceContext;

		let policy = parse_policy_toml(SAMPLE_POLICY).unwrap();
		let effective = policy.effective("openclaw");

		// nginx allowed
		let ctx = ResourceContext {
			service_name: Some("nginx".into()),
			..Default::default()
		};
		assert!(effective.evaluate("service_action", Some(&ctx)).allowed);

		// mysql denied
		let ctx = ResourceContext {
			service_name: Some("mysql".into()),
			..Default::default()
		};
		assert!(!effective.evaluate("service_action", Some(&ctx)).allowed);
	}

	#[test]
	fn global_tunable_prefix_filter() {
		use mycelium_core::policy::rule::ResourceContext;

		let policy = parse_policy_toml(SAMPLE_POLICY).unwrap();
		// Use operator (default) profile
		let effective = policy.effective("operator");

		// kernel.* denied by global rule
		let ctx = ResourceContext {
			tunable_key: Some("kernel.panic".into()),
			..Default::default()
		};
		assert!(!effective.evaluate("tuning_set", Some(&ctx)).allowed);
	}

	#[test]
	fn unknown_agent_falls_back_to_global() {
		use mycelium_core::policy::rule::ResourceContext;
		let policy = parse_policy_toml(SAMPLE_POLICY).unwrap();
		// No profile named "operator" exists (the operator-role profile is "openclaw").
		// Unknown agent gets global rules only.
		let effective = policy.effective("unknown-agent");

		// Global rules allow everything except probes and kernel.* tunables
		assert!(effective.evaluate("process_list", None).allowed);
		assert!(effective.evaluate("process_kill", None).allowed);
		assert!(!effective.evaluate("probe_attach", None).allowed);

		// kernel.* tunable denied via global filter
		let ctx = ResourceContext {
			tunable_key: Some("kernel.panic".into()),
			..Default::default()
		};
		assert!(!effective.evaluate("tuning_set", Some(&ctx)).allowed);
	}
}
