use clap::{Subcommand, ValueEnum};
use mycelium_core::platform::Platform;
use mycelium_core::types::{ProcessInfo, ProcessResource, Signal};

use crate::output::*;

#[derive(Clone, ValueEnum)]
pub enum SignalArg {
	Term,
	Kill,
	Hup,
	Int,
	Usr1,
	Usr2,
	Stop,
	Cont,
}

impl SignalArg {
	fn to_signal(&self) -> Signal {
		match self {
			Self::Term => Signal::Term,
			Self::Kill => Signal::Kill,
			Self::Hup => Signal::Hup,
			Self::Int => Signal::Int,
			Self::Usr1 => Signal::Usr1,
			Self::Usr2 => Signal::Usr2,
			Self::Stop => Signal::Stop,
			Self::Cont => Signal::Cont,
		}
	}
}

#[derive(Subcommand)]
pub enum ProcessCmd {
	/// List all running processes
	List,
	/// Inspect a single process
	Inspect {
		/// Process ID
		pid: u32,
	},
	/// Show resource usage for a process
	Resources {
		/// Process ID
		pid: u32,
	},
	/// Send a signal to a process
	Kill {
		/// Process ID
		pid: u32,
		/// Signal to send
		#[arg(default_value = "term")]
		signal: SignalArg,
	},
}

impl ProcessCmd {
	pub fn run(&self, platform: &dyn Platform, format: OutputFormat, dry_run: bool) {
		match self {
			Self::List => match platform.list_processes() {
				Ok(procs) => print_list(&procs, format),
				Err(e) => eprintln!("error: {e}"),
			},
			Self::Inspect { pid } => match platform.inspect_process(*pid) {
				Ok(info) => print_output(&info, format),
				Err(e) => eprintln!("error: {e}"),
			},
			Self::Resources { pid } => match platform.process_resources(*pid) {
				Ok(res) => print_output(&res, format),
				Err(e) => eprintln!("error: {e}"),
			},
			Self::Kill { pid, signal } => {
				let sig = signal.to_signal();
				if dry_run {
					println!("[dry-run] would send {sig:?} to process {pid}");
					return;
				}
				match platform.kill_process(*pid, sig) {
					Ok(()) => println!("sent {sig:?} to process {pid}"),
					Err(e) => eprintln!("error: {e}"),
				}
			}
		}
	}
}

impl TableDisplay for ProcessInfo {
	fn print_header() {
		println!(
			"{:<7} {:<7} {:<20} {:<10} {:<12} {:>8} {:>12}  COMMAND",
			"PID", "PPID", "NAME", "STATE", "USER", "THR", "MEM"
		);
	}

	fn print_row(&self) {
		let state = format!("{:?}", self.state);
		println!(
			"{:<7} {:<7} {:<20} {:<10} {:<12} {:>8} {:>12}  {}",
			self.pid,
			self.ppid,
			truncate(&self.name, 20),
			state,
			truncate(&self.user, 12),
			self.threads,
			human_bytes(self.memory_bytes),
			truncate(&self.command, 50),
		);
	}
}

impl TableDisplay for ProcessResource {
	fn print_header() {
		println!(
			"{:<7} {:>6} {:>12} {:>7} {:>12} {:>6} {:>6} {:>12} {:>12}",
			"PID", "CPU%", "MEM", "MEM%", "VMEM", "FDS", "THR", "READ", "WRITE"
		);
	}

	fn print_row(&self) {
		println!(
			"{:<7} {:>5.1}% {:>12} {:>6.1}% {:>12} {:>6} {:>6} {:>12} {:>12}",
			self.pid,
			self.cpu_percent,
			human_bytes(self.memory_bytes),
			self.memory_percent,
			human_bytes(self.virtual_memory_bytes),
			self.open_fds,
			self.threads,
			human_bytes(self.read_bytes),
			human_bytes(self.write_bytes),
		);
	}
}
