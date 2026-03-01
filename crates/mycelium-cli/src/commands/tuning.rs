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
}

impl TuningCmd {
	pub fn run(&self, platform: &dyn Platform, format: OutputFormat) {
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
		}
	}
}

impl TableDisplay for TunableParam {
	fn print_header() {
		println!("{:<50} {}", "KEY", "VALUE");
	}

	fn print_row(&self) {
		println!("{:<50} {}", self.key, self.value);
	}
}
