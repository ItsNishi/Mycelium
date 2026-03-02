use clap::Subcommand;
use mycelium_core::platform::Platform;
use mycelium_core::types::*;

use crate::output::*;

#[derive(Subcommand)]
pub enum SystemCmd {
	/// Show system information
	Info,
	/// Show kernel information
	Kernel,
	/// Show CPU information
	Cpu,
	/// Show system uptime
	Uptime,
}

impl SystemCmd {
	pub fn run(&self, platform: &dyn Platform, format: OutputFormat) {
		match self {
			Self::Info => match platform.system_info() {
				Ok(info) => print_output(&info, format),
				Err(e) => eprintln!("error: {e}"),
			},
			Self::Kernel => match platform.kernel_info() {
				Ok(info) => print_output(&info, format),
				Err(e) => eprintln!("error: {e}"),
			},
			Self::Cpu => match platform.cpu_info() {
				Ok(info) => print_output(&info, format),
				Err(e) => eprintln!("error: {e}"),
			},
			Self::Uptime => match platform.uptime() {
				Ok(secs) => {
					if format == OutputFormat::Json {
						println!("{{\"uptime_seconds\": {secs}}}");
					} else {
						println!("Uptime: {}", human_uptime(secs));
					}
				}
				Err(e) => eprintln!("error: {e}"),
			},
		}
	}
}

impl TableDisplay for SystemInfo {
	fn print_header() {}

	fn print_row(&self) {
		println!("Hostname:      {}", self.hostname);
		println!("OS:            {} {}", self.os_name, self.os_version);
		println!("Architecture:  {}", self.architecture);
		println!("Uptime:        {}", human_uptime(self.uptime_seconds));
	}
}

impl TableDisplay for KernelInfo {
	fn print_header() {}

	fn print_row(&self) {
		println!("Release:       {}", self.release);
		println!("Version:       {}", self.version);
		println!("Architecture:  {}", self.architecture);
		println!("Command Line:  {}", truncate(&self.command_line, 100));
	}
}

impl TableDisplay for CpuInfo {
	fn print_header() {}

	fn print_row(&self) {
		println!("Model:         {}", self.model_name);
		println!(
			"Cores:         {} physical, {} logical",
			self.cores_physical, self.cores_logical
		);
		println!("Frequency:     {:.0} MHz", self.frequency_mhz);
		println!("Cache:         {} KiB", self.cache_size_kb);
		println!(
			"Load Average:  {:.2}, {:.2}, {:.2}",
			self.load_average[0], self.load_average[1], self.load_average[2]
		);
		println!("Usage:         {:.1}%", self.usage_percent);
	}
}
