use clap::Subcommand;
use mycelium_core::platform::Platform;
use mycelium_core::types::{MemoryInfo, ProcessMemory};

use crate::output::*;

#[derive(Subcommand)]
pub enum MemoryCmd {
	/// Show system memory information
	Info,
	/// Show memory details for a process
	Process {
		/// Process ID
		pid: u32,
	},
}

impl MemoryCmd {
	pub fn run(&self, platform: &dyn Platform, format: OutputFormat) {
		match self {
			Self::Info => match platform.memory_info() {
				Ok(info) => print_output(&info, format),
				Err(e) => eprintln!("error: {e}"),
			},
			Self::Process { pid } => match platform.process_memory(*pid) {
				Ok(mem) => print_output(&mem, format),
				Err(e) => eprintln!("error: {e}"),
			},
		}
	}
}

impl TableDisplay for MemoryInfo {
	fn print_header() {
		println!(
			"{:<14} {:>12} {:>12} {:>12} {:>12} {:>12}",
			"", "TOTAL", "USED", "AVAILABLE", "BUFFERS", "CACHED"
		);
	}

	fn print_row(&self) {
		println!(
			"{:<14} {:>12} {:>12} {:>12} {:>12} {:>12}",
			"Memory",
			human_bytes(self.total_bytes),
			human_bytes(self.used_bytes),
			human_bytes(self.available_bytes),
			human_bytes(self.buffers_bytes),
			human_bytes(self.cached_bytes),
		);
		println!(
			"{:<14} {:>12} {:>12} {:>12}",
			"Swap",
			human_bytes(self.swap.total_bytes),
			human_bytes(self.swap.used_bytes),
			human_bytes(self.swap.free_bytes),
		);
	}
}

impl TableDisplay for ProcessMemory {
	fn print_header() {
		println!(
			"{:<7} {:>12} {:>12} {:>12} {:>12} {:>12}",
			"PID", "RSS", "VIRTUAL", "SHARED", "TEXT", "DATA"
		);
	}

	fn print_row(&self) {
		println!(
			"{:<7} {:>12} {:>12} {:>12} {:>12} {:>12}",
			self.pid,
			human_bytes(self.rss_bytes),
			human_bytes(self.virtual_bytes),
			human_bytes(self.shared_bytes),
			human_bytes(self.text_bytes),
			human_bytes(self.data_bytes),
		);
	}
}
