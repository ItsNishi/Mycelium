use clap::Subcommand;
use mycelium_core::platform::Platform;
use mycelium_core::types::*;

use crate::output::*;

#[derive(Subcommand)]
pub enum ServiceCmd {
	/// List all services
	List,
	/// Show status of a single service
	Status {
		/// Service name
		name: String,
	},
}

impl ServiceCmd {
	pub fn run(&self, platform: &dyn Platform, format: OutputFormat) {
		match self {
			Self::List => match platform.list_services() {
				Ok(services) => print_list(&services, format),
				Err(e) => eprintln!("error: {e}"),
			},
			Self::Status { name } => match platform.service_status(name) {
				Ok(info) => print_output(&info, format),
				Err(e) => eprintln!("error: {e}"),
			},
		}
	}
}

impl TableDisplay for ServiceInfo {
	fn print_header() {
		println!(
			"{:<30} {:<10} {:<8} {:>7} DESCRIPTION",
			"NAME", "STATE", "ENABLED", "PID"
		);
	}

	fn print_row(&self) {
		let state = format!("{:?}", self.state);
		println!(
			"{:<30} {:<10} {:<8} {:>7} {}",
			truncate(&self.name, 30),
			state,
			if self.enabled { "yes" } else { "no" },
			self.pid.map(|p| p.to_string()).unwrap_or_default(),
			self.description.as_deref().unwrap_or("-"),
		);
	}
}
