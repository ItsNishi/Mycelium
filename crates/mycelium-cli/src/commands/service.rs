use clap::{Subcommand, ValueEnum};
use mycelium_core::platform::Platform;
use mycelium_core::types::*;

use crate::output::*;

#[derive(Clone, ValueEnum)]
pub enum ServiceActionArg {
	Start,
	Stop,
	Restart,
	Reload,
	Enable,
	Disable,
}

impl ServiceActionArg {
	fn to_action(&self) -> ServiceAction {
		match self {
			Self::Start => ServiceAction::Start,
			Self::Stop => ServiceAction::Stop,
			Self::Restart => ServiceAction::Restart,
			Self::Reload => ServiceAction::Reload,
			Self::Enable => ServiceAction::Enable,
			Self::Disable => ServiceAction::Disable,
		}
	}
}

#[derive(Subcommand)]
pub enum ServiceCmd {
	/// List all services
	List,
	/// Show status of a single service
	Status {
		/// Service name
		name: String,
	},
	/// Perform an action on a service
	Action {
		/// Service name
		name: String,
		/// Action to perform
		action: ServiceActionArg,
	},
}

impl ServiceCmd {
	pub fn run(&self, platform: &dyn Platform, format: OutputFormat, dry_run: bool) {
		match self {
			Self::List => match platform.list_services() {
				Ok(services) => print_list(&services, format),
				Err(e) => eprintln!("error: {e}"),
			},
			Self::Status { name } => match platform.service_status(name) {
				Ok(info) => print_output(&info, format),
				Err(e) => eprintln!("error: {e}"),
			},
			Self::Action { name, action } => {
				let svc_action = action.to_action();
				if dry_run {
					println!("[dry-run] would {svc_action:?} service {name}");
					return;
				}
				match platform.service_action(name, svc_action) {
					Ok(()) => println!("{:?} {name}: ok", svc_action),
					Err(e) => eprintln!("error: {e}"),
				}
			}
		}
	}
}

impl TableDisplay for ServiceInfo {
	fn print_header() {
		println!(
			"{:<30} {:<10} {:<8} {:>7} {:<30} DESCRIPTION",
			"NAME", "STATE", "ENABLED", "PID", "DEPENDS"
		);
	}

	fn print_row(&self) {
		let state = format!("{:?}", self.state);
		let deps = if self.dependencies.is_empty() {
			"-".to_string()
		} else {
			truncate(&self.dependencies.join(","), 30)
		};
		println!(
			"{:<30} {:<10} {:<8} {:>7} {:<30} {}",
			truncate(&self.name, 30),
			state,
			if self.enabled { "yes" } else { "no" },
			self.pid.map(|p| p.to_string()).unwrap_or_default(),
			deps,
			self.description.as_deref().unwrap_or("-"),
		);
	}
}
