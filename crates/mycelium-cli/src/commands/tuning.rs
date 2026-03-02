use clap::Subcommand;
use mycelium_core::platform::Platform;
use mycelium_core::types::*;

use crate::output::*;

#[derive(Subcommand)]
pub enum TuningCmd {
	/// Get a single tunable value
	Get {
		/// Sysctl key (e.g. net.ipv4.ip_forward)
		key: String,
	},
	/// List tunables matching a prefix
	List {
		/// Prefix to filter (e.g. net.ipv4)
		#[arg(default_value = "")]
		prefix: String,
	},
	/// Set a kernel tunable value
	Set {
		/// Sysctl key (e.g. net.ipv4.ip_forward)
		key: String,
		/// Value to set
		value: String,
	},
}

impl TuningCmd {
	pub fn run(&self, platform: &dyn Platform, format: OutputFormat, dry_run: bool) {
		match self {
			Self::Get { key } => match platform.get_tunable(key) {
				Ok(val) => {
					if format == OutputFormat::Json {
						println!(
							"{{\"key\": {}, \"value\": {}}}",
							serde_json::to_string(key).unwrap_or_default(),
							serde_json::to_string(&val.to_string()).unwrap_or_default()
						);
					} else {
						println!("{key} = {val}");
					}
				}
				Err(e) => eprintln!("error: {e}"),
			},
			Self::List { prefix } => match platform.list_tunables(prefix) {
				Ok(params) => print_list(&params, format),
				Err(e) => eprintln!("error: {e}"),
			},
			Self::Set { key, value } => {
				let tunable_value = parse_cli_tunable(value);
				if dry_run {
					println!("[dry-run] would set {key} = {tunable_value}");
					return;
				}
				match platform.set_tunable(key, &tunable_value) {
					Ok(previous) => {
						println!("{key}: {previous} -> {tunable_value}");
					}
					Err(e) => eprintln!("error: {e}"),
				}
			}
		}
	}
}

fn parse_cli_tunable(s: &str) -> TunableValue {
	if let Ok(n) = s.parse::<i64>() {
		TunableValue::Integer(n)
	} else {
		TunableValue::String(s.to_string())
	}
}

impl TableDisplay for TunableParam {
	fn print_header() {
		println!("{:<50} VALUE", "KEY");
	}

	fn print_row(&self) {
		println!("{:<50} {}", self.key, self.value);
	}
}
