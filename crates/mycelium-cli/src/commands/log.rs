use clap::Args;
use mycelium_core::platform::Platform;
use mycelium_core::types::*;

use crate::output::*;

#[derive(Args)]
pub struct LogCmd {
	/// Filter by systemd unit
	#[arg(short, long)]
	pub unit: Option<String>,

	/// Minimum log level (emergency, alert, critical, error, warning, notice, info, debug)
	#[arg(short, long)]
	pub level: Option<String>,

	/// Maximum number of entries
	#[arg(short = 'n', long, default_value = "50")]
	pub limit: u32,

	/// Filter messages containing this pattern
	#[arg(short, long)]
	pub grep: Option<String>,

	/// Show entries since this Unix timestamp
	#[arg(long)]
	pub since: Option<u64>,

	/// Show entries until this Unix timestamp
	#[arg(long)]
	pub until: Option<u64>,
}

impl LogCmd {
	pub fn run(&self, platform: &dyn Platform, format: OutputFormat) {
		let level = self.level.as_ref().map(|l| match l.to_lowercase().as_str() {
			"emergency" | "emerg" => LogLevel::Emergency,
			"alert" => LogLevel::Alert,
			"critical" | "crit" => LogLevel::Critical,
			"error" | "err" => LogLevel::Error,
			"warning" | "warn" => LogLevel::Warning,
			"notice" => LogLevel::Notice,
			"info" => LogLevel::Info,
			"debug" => LogLevel::Debug,
			_ => LogLevel::Info,
		});

		let query = LogQuery {
			unit: self.unit.clone(),
			level,
			since: self.since,
			until: self.until,
			limit: Some(self.limit),
			grep: self.grep.clone(),
		};

		match platform.read_logs(&query) {
			Ok(entries) => print_list(&entries, format),
			Err(e) => eprintln!("error: {e}"),
		}
	}
}

impl TableDisplay for LogEntry {
	fn print_header() {
		println!(
			"{:<12} {:<7} {:<20} MESSAGE",
			"TIMESTAMP", "LEVEL", "UNIT"
		);
	}

	fn print_row(&self) {
		let level = format!("{:?}", self.level);
		println!(
			"{:<12} {:<7} {:<20} {}",
			self.timestamp,
			level,
			self.unit.as_deref().unwrap_or("-"),
			truncate(&self.message, 80),
		);
	}
}
