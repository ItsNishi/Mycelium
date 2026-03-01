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
		}
	}
}

impl TableDisplay for UserInfo {
	fn print_header() {
		println!(
			"{:<20} {:>6} {:>6} {:<25} {:<20} {}",
			"NAME", "UID", "GID", "HOME", "SHELL", "GROUPS"
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
		println!("{:<20} {:>6} {}", "NAME", "GID", "MEMBERS");
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
			"{:<25} {:>12} {:<10} {}",
			"NAME", "SIZE", "STATE", "USED_BY"
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
