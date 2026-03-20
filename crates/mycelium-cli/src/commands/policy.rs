use clap::Subcommand;
use mycelium_core::policy::config::{load_policy, parse_policy_toml};
use mycelium_core::policy::rule::{Action, PolicyRule, RuleTarget};

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
					let rules: Vec<RuleDisplay> =
						effective.rules().iter().map(RuleDisplay::from).collect();
					match serde_json::to_string_pretty(&rules) {
						Ok(json) => println!("{json}"),
						Err(e) => eprintln!("error: {e}"),
					}
				} else {
					println!("Effective policy for profile: {profile}");
					println!("Dry-run: {}", effective.is_dry_run());
					println!();
					println!("{:<8} {:<30} REASON", "ACTION", "TARGET");
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
						let profile = policy.profiles.iter().find(|p| p.name == *name).unwrap();
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
			Self::Validate { path } => match std::fs::read_to_string(path) {
				Ok(content) => match parse_policy_toml(&content) {
					Ok(policy) => {
						println!("Policy file is valid.");
						println!("  Profiles: {}", policy.profile_names().join(", "));
						println!("  Default: {}", policy.default_profile);
						println!("  Global rules: {}", policy.global_rules.len());
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
			},
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
