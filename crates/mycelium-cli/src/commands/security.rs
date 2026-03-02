use clap::Subcommand;
use mycelium_core::platform::Platform;
use mycelium_core::types::*;

use crate::output::*;

#[derive(Subcommand)]
pub enum SecurityCmd {
	/// List system users
	Users,
	/// List system groups
	Groups,
	/// List loaded kernel modules
	Modules,
	/// Show security status (LSM, firewall, SSH)
	Status,
	/// Scan persistence mechanisms
	Persistence,
	/// Detect API hooks in a process
	DetectHooks {
		/// Process ID
		pid: u32,
	},
}

impl SecurityCmd {
	pub fn run(&self, platform: &dyn Platform, format: OutputFormat) {
		match self {
			Self::Users => match platform.list_users() {
				Ok(users) => print_list(&users, format),
				Err(e) => eprintln!("error: {e}"),
			},
			Self::Groups => match platform.list_groups() {
				Ok(groups) => print_list(&groups, format),
				Err(e) => eprintln!("error: {e}"),
			},
			Self::Modules => match platform.list_kernel_modules() {
				Ok(mods) => print_list(&mods, format),
				Err(e) => eprintln!("error: {e}"),
			},
			Self::Status => match platform.security_status() {
				Ok(status) => print_output(&status, format),
				Err(e) => eprintln!("error: {e}"),
			},
			Self::Persistence => match platform.list_persistence_entries() {
				Ok(entries) => print_list(&entries, format),
				Err(e) => eprintln!("error: {e}"),
			},
			Self::DetectHooks { pid } => match platform.detect_hooks(*pid) {
				Ok(hooks) => print_list(&hooks, format),
				Err(e) => eprintln!("error: {e}"),
			},
		}
	}
}

impl TableDisplay for UserInfo {
	fn print_header() {
		println!(
			"{:<20} {:>6} {:>6} {:<25} {:<20} GROUPS",
			"NAME", "UID", "GID", "HOME", "SHELL"
		);
	}

	fn print_row(&self) {
		println!(
			"{:<20} {:>6} {:>6} {:<25} {:<20} {}",
			self.name,
			self.uid,
			self.gid,
			truncate(&self.home, 25),
			truncate(&self.shell, 20),
			self.groups.join(","),
		);
	}
}

impl TableDisplay for GroupInfo {
	fn print_header() {
		println!("{:<20} {:>6} MEMBERS", "NAME", "GID");
	}

	fn print_row(&self) {
		println!(
			"{:<20} {:>6} {}",
			self.name,
			self.gid,
			self.members.join(","),
		);
	}
}

impl TableDisplay for KernelModule {
	fn print_header() {
		println!(
			"{:<25} {:>12} {:<10} USED_BY",
			"NAME", "SIZE", "STATE"
		);
	}

	fn print_row(&self) {
		let state = format!("{:?}", self.state);
		println!(
			"{:<25} {:>12} {:<10} {}",
			self.name,
			human_bytes(self.size_bytes),
			state,
			self.used_by.join(","),
		);
	}
}

fn persistence_type_name(pt: &PersistenceType) -> &'static str {
	match pt {
		PersistenceType::RegistryRun => "RegistryRun",
		PersistenceType::ScheduledTask => "SchedTask",
		PersistenceType::Service => "Service",
		PersistenceType::StartupFolder => "Startup",
		PersistenceType::WmiSubscription => "WMI",
		PersistenceType::ComHijack => "COMHijack",
	}
}

impl TableDisplay for PersistenceEntry {
	fn print_header() {
		println!(
			"{:<12} {:<25} {:<40} COMMAND",
			"TYPE", "NAME", "LOCATION"
		);
	}

	fn print_row(&self) {
		println!(
			"{:<12} {:<25} {:<40} {}",
			persistence_type_name(&self.persistence_type),
			truncate(&self.name, 25),
			truncate(&self.location, 40),
			truncate(&self.value, 60),
		);
	}
}

fn hook_type_name(ht: &HookType) -> &'static str {
	match ht {
		HookType::InlineHook => "Inline",
		HookType::IatHook => "IAT",
		HookType::EatHook => "EAT",
	}
}

impl TableDisplay for HookInfo {
	fn print_header() {
		println!(
			"{:<8} {:<20} {:<30} {:>16} DESTINATION",
			"TYPE", "MODULE", "FUNCTION", "ADDRESS"
		);
	}

	fn print_row(&self) {
		println!(
			"{:<8} {:<20} {:<30} 0x{:014x} {}",
			hook_type_name(&self.hook_type),
			truncate(&self.module, 20),
			truncate(&self.function, 30),
			self.address,
			self.destination_module.as_deref().unwrap_or(""),
		);
	}
}

impl TableDisplay for SecurityStatus {
	fn print_header() {}

	fn print_row(&self) {
		match &self.selinux {
			Some(s) => println!(
				"SELinux:           {} ({})",
				if s.enabled { "enabled" } else { "disabled" },
				s.mode
			),
			None => println!("SELinux:           not available"),
		}
		match &self.apparmor {
			Some(s) => println!(
				"AppArmor:          {} ({})",
				if s.enabled { "enabled" } else { "disabled" },
				s.mode
			),
			None => println!("AppArmor:          not available"),
		}
		println!(
			"Firewall:          {}",
			if self.firewall_active {
				"active"
			} else {
				"inactive"
			}
		);
		println!(
			"Root Login (SSH):  {}",
			if self.root_login_allowed {
				"allowed"
			} else {
				"denied"
			}
		);
		println!(
			"Password Auth:     {}",
			if self.password_auth_ssh {
				"enabled"
			} else {
				"disabled"
			}
		);
	}
}
