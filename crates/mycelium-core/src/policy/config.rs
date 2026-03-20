//! TOML-based policy configuration loading.

use std::collections::HashMap;

use super::Policy;
use super::RateLimit;
use super::capability::Capability;
use super::profile::Profile;
use super::rule::{Action, PolicyRule, ResourceFilter, RuleTarget};
use crate::policy::Role;

/// Parse a TOML string into a Policy.
pub fn parse_policy_toml(content: &str) -> Result<Policy, String> {
	let table: toml::Value = content
		.parse()
		.map_err(|e| format!("TOML parse error: {e}"))?;

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
		.map(|arr| arr.iter().filter_map(parse_rule).collect())
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

	let rate_limits = table
		.get("rate_limits")
		.and_then(|v| v.as_table())
		.map(parse_rate_limits)
		.unwrap_or_default();

	Ok(Policy {
		global_rules,
		profiles,
		default_profile,
		dry_run,
		rate_limits,
	})
}

/// Load policy from a config file path or the default XDG location.
pub fn load_policy(config_path: Option<&str>) -> Policy {
	let path = config_path
		.map(|p| p.to_string())
		.or_else(|| dirs_path("mycelium/policy.toml"));

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

/// Resolve the XDG config path for a relative path.
pub fn dirs_path(relative: &str) -> Option<String> {
	let config_dir = std::env::var("XDG_CONFIG_HOME").ok().unwrap_or_else(|| {
		let home = std::env::var("HOME").unwrap_or_default();
		format!("{home}/.config")
	});
	let path = format!("{config_dir}/{relative}");
	Some(path)
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

fn parse_rate_limits(table: &toml::map::Map<String, toml::Value>) -> HashMap<String, RateLimit> {
	let mut limits = HashMap::new();
	for (tool, val) in table {
		let max_calls = val
			.get("max_calls")
			.and_then(|v| v.as_integer())
			.unwrap_or(0) as u32;
		let window_secs = val
			.get("window_secs")
			.and_then(|v| v.as_integer())
			.unwrap_or(60) as u64;
		if max_calls > 0 {
			limits.insert(
				tool.clone(),
				RateLimit {
					max_calls,
					window_secs,
				},
			);
		}
	}
	limits
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
		.map(|arr| arr.iter().filter_map(parse_rule).collect())
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
	use crate::policy::rule::ResourceContext;

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

[rate_limits]
process_kill = { max_calls = 5, window_secs = 60 }
memory_write = { max_calls = 10, window_secs = 60 }
service_action = { max_calls = 10, window_secs = 60 }
tuning_set = { max_calls = 3, window_secs = 60 }
firewall_add = { max_calls = 5, window_secs = 60 }
firewall_remove = { max_calls = 5, window_secs = 60 }
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
		let policy = parse_policy_toml(SAMPLE_POLICY).unwrap();
		let effective = policy.effective("openclaw");

		let ctx = ResourceContext {
			service_name: Some("nginx".into()),
			..Default::default()
		};
		assert!(effective.evaluate("service_action", Some(&ctx)).allowed);

		let ctx = ResourceContext {
			service_name: Some("mysql".into()),
			..Default::default()
		};
		assert!(!effective.evaluate("service_action", Some(&ctx)).allowed);
	}

	#[test]
	fn global_tunable_prefix_filter() {
		let policy = parse_policy_toml(SAMPLE_POLICY).unwrap();
		let effective = policy.effective("operator");

		let ctx = ResourceContext {
			tunable_key: Some("kernel.panic".into()),
			..Default::default()
		};
		assert!(!effective.evaluate("tuning_set", Some(&ctx)).allowed);
	}

	#[test]
	fn parse_rate_limits_section() {
		let policy = parse_policy_toml(SAMPLE_POLICY).unwrap();
		assert_eq!(policy.rate_limits.len(), 6);

		let pk = policy.rate_limits.get("process_kill").unwrap();
		assert_eq!(pk.max_calls, 5);
		assert_eq!(pk.window_secs, 60);

		let ts = policy.rate_limits.get("tuning_set").unwrap();
		assert_eq!(ts.max_calls, 3);
		assert_eq!(ts.window_secs, 60);
	}

	#[test]
	fn no_rate_limits_defaults_to_empty() {
		let toml = r#"
[global]
default_profile = "default"
"#;
		let policy = parse_policy_toml(toml).unwrap();
		assert!(policy.rate_limits.is_empty());
	}

	#[test]
	fn unknown_agent_falls_back_to_global() {
		let policy = parse_policy_toml(SAMPLE_POLICY).unwrap();
		let effective = policy.effective("unknown-agent");

		assert!(effective.evaluate("process_list", None).allowed);
		assert!(effective.evaluate("process_kill", None).allowed);
		assert!(!effective.evaluate("probe_attach", None).allowed);

		let ctx = ResourceContext {
			tunable_key: Some("kernel.panic".into()),
			..Default::default()
		};
		assert!(!effective.evaluate("tuning_set", Some(&ctx)).allowed);
	}
}
