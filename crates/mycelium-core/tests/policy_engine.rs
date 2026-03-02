//! End-to-end policy engine integration tests.
//!
//! These parse TOML strings through the full pipeline and evaluate decisions.
//! No root or platform access needed.
//!
//! Requires the `toml` feature:
//!   `cargo test --test policy_engine -p mycelium-core --features toml`

#![cfg(feature = "toml")]

#[test]
fn full_policy_load_and_evaluate() {
	use mycelium_core::policy::config::parse_policy_toml;
	use mycelium_core::policy::rule::ResourceContext;

	let toml = r#"
[global]
default_profile = "operator"
dry_run = false

[[global.rules]]
action = "allow"
target = "all"

[[global.rules]]
action = "deny"
target = { capability = "probe_manage" }
reason = "probes disabled globally"

[profiles.admin-bot]
role = "admin"

[[profiles.admin-bot.rules]]
action = "allow"
target = { capability = "probe_manage" }

[profiles.reader]
role = "read-only"
dry_run = true

[profiles.scoped-ops]
role = "operator"

[[profiles.scoped-ops.rules]]
action = "allow"
target = { tool = "service_action" }
filter = { service_names = ["nginx", "redis"] }

[[profiles.scoped-ops.rules]]
action = "deny"
target = { tool = "service_action" }
reason = "only nginx and redis"

[rate_limits]
process_kill = { max_calls = 5, window_secs = 60 }
"#;

	let policy = parse_policy_toml(toml).unwrap();

	// Admin can do everything including probes.
	let admin = policy.effective("admin-bot");
	assert!(admin.evaluate("probe_attach", None).allowed);
	assert!(admin.evaluate("process_kill", None).allowed);
	assert!(admin.evaluate("tuning_set", None).allowed);

	// Reader is read-only and dry-run.
	let reader = policy.effective("reader");
	assert!(reader.is_dry_run());
	assert!(reader.evaluate("process_list", None).allowed);
	assert!(!reader.evaluate("process_kill", None).allowed);
	assert!(!reader.evaluate("probe_attach", None).allowed);

	// Scoped ops can manage nginx/redis but not other services.
	let scoped = policy.effective("scoped-ops");
	let ctx_nginx = ResourceContext {
		service_name: Some("nginx".into()),
		..Default::default()
	};
	assert!(scoped.evaluate("service_action", Some(&ctx_nginx)).allowed);

	let ctx_mysql = ResourceContext {
		service_name: Some("mysql".into()),
		..Default::default()
	};
	assert!(!scoped.evaluate("service_action", Some(&ctx_mysql)).allowed);

	// Unknown agent falls back to default profile (operator).
	let unknown = policy.effective("unknown-agent");
	assert!(unknown.evaluate("process_list", None).allowed);
	assert!(unknown.evaluate("process_kill", None).allowed);
	assert!(!unknown.evaluate("probe_attach", None).allowed);

	// Rate limits parsed correctly.
	assert_eq!(policy.rate_limits.len(), 1);
	let pk = policy.rate_limits.get("process_kill").unwrap();
	assert_eq!(pk.max_calls, 5);
	assert_eq!(pk.window_secs, 60);
}

#[test]
fn empty_toml_defaults() {
	use mycelium_core::policy::config::parse_policy_toml;

	let policy = parse_policy_toml("").unwrap();
	assert_eq!(policy.default_profile, "default");
	assert!(!policy.dry_run);
	assert!(policy.global_rules.is_empty());
	assert!(policy.profiles.is_empty());
	assert!(policy.rate_limits.is_empty());

	// With no rules at all, everything defaults to deny (no matching rule).
	let effective = policy.effective("anything");
	assert!(!effective.evaluate("process_list", None).allowed);
}

#[test]
fn malformed_toml_errors() {
	use mycelium_core::policy::config::parse_policy_toml;

	let result = parse_policy_toml("this is not [valid toml = {");
	assert!(result.is_err());
	let err = result.unwrap_err();
	assert!(
		err.contains("TOML"),
		"error should mention TOML: {err}"
	);
}

#[test]
fn cascading_overrides() {
	use mycelium_core::policy::config::parse_policy_toml;

	let toml = r#"
[[global.rules]]
action = "deny"
target = "all"
reason = "deny everything globally"

[profiles.special]
role = "custom"

[[profiles.special.rules]]
action = "allow"
target = { tool = "process_list" }
reason = "special can list processes"
"#;

	let policy = parse_policy_toml(toml).unwrap();
	let effective = policy.effective("special");

	// The profile allow for process_list should win (higher specificity).
	assert!(effective.evaluate("process_list", None).allowed);
	// Everything else should be denied by the global deny-all.
	assert!(!effective.evaluate("process_kill", None).allowed);
	assert!(!effective.evaluate("probe_attach", None).allowed);
}

#[test]
fn rate_limit_config_integration() {
	use mycelium_core::policy::config::parse_policy_toml;

	let toml = r#"
[rate_limits]
process_kill = { max_calls = 3, window_secs = 30 }
memory_write = { max_calls = 10, window_secs = 120 }
tuning_set = { max_calls = 1, window_secs = 300 }
"#;

	let policy = parse_policy_toml(toml).unwrap();
	assert_eq!(policy.rate_limits.len(), 3);

	let ts = policy.rate_limits.get("tuning_set").unwrap();
	assert_eq!(ts.max_calls, 1);
	assert_eq!(ts.window_secs, 300);

	let mw = policy.rate_limits.get("memory_write").unwrap();
	assert_eq!(mw.max_calls, 10);
	assert_eq!(mw.window_secs, 120);
}

#[test]
fn resource_filter_evaluation() {
	use mycelium_core::policy::config::parse_policy_toml;
	use mycelium_core::policy::rule::ResourceContext;

	let toml = r#"
[[global.rules]]
action = "allow"
target = "all"

[profiles.limited]
role = "custom"

[[profiles.limited.rules]]
action = "allow"
target = { tool = "service_action" }
filter = { service_names = ["nginx", "redis"] }

[[profiles.limited.rules]]
action = "deny"
target = { tool = "service_action" }
reason = "only nginx and redis"
"#;

	let policy = parse_policy_toml(toml).unwrap();
	let effective = policy.effective("limited");

	// Matching service.
	let ctx = ResourceContext {
		service_name: Some("nginx".into()),
		..Default::default()
	};
	let decision = effective.evaluate("service_action", Some(&ctx));
	assert!(decision.allowed, "nginx should be allowed");

	let ctx = ResourceContext {
		service_name: Some("redis".into()),
		..Default::default()
	};
	assert!(
		effective.evaluate("service_action", Some(&ctx)).allowed,
		"redis should be allowed"
	);

	// Non-matching service.
	let ctx = ResourceContext {
		service_name: Some("postgresql".into()),
		..Default::default()
	};
	let decision = effective.evaluate("service_action", Some(&ctx));
	assert!(!decision.allowed, "postgresql should be denied");

	// No context provided -- filter doesn't match, falls to unfiltered deny.
	let decision = effective.evaluate("service_action", None);
	assert!(!decision.allowed, "no context should be denied");
}
