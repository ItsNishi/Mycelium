use clap::{Subcommand, ValueEnum};
use mycelium_core::platform::Platform;
use mycelium_core::types::{
	ElfInfo, ElfSection, ElfSymbol, ElfTarget, HandleInfo, PeExport, PeImport, PeInfo, PeSection,
	PeTarget, PrivilegeInfo, ProcessInfo, ProcessResource, Signal, TokenGroup, TokenInfo,
};

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
	/// Show environment variables for a process
	Env {
		/// Process ID
		pid: u32,
	},
	/// List token privileges for a process
	Privileges {
		/// Process ID
		pid: u32,
	},
	/// List open handles for a process
	Handles {
		/// Process ID
		pid: u32,
	},
	/// Parse PE headers of a process or file
	Pe {
		/// Process ID (mutually exclusive with --path)
		#[arg(conflicts_with = "path")]
		pid: Option<u32>,
		/// Path to a PE file (mutually exclusive with pid)
		#[arg(long)]
		path: Option<String>,
	},
	/// Parse ELF headers of a process or file
	Elf {
		/// Process ID (mutually exclusive with --path)
		#[arg(conflicts_with = "path")]
		pid: Option<u32>,
		/// Path to an ELF file (mutually exclusive with pid)
		#[arg(long)]
		path: Option<String>,
	},
	/// Inspect process token security details
	Token {
		/// Process ID
		pid: u32,
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
			Self::Privileges { pid } => match platform.list_process_privileges(*pid) {
				Ok(privs) => print_list(&privs, format),
				Err(e) => eprintln!("error: {e}"),
			},
			Self::Handles { pid } => match platform.list_process_handles(*pid) {
				Ok(handles) => print_list(&handles, format),
				Err(e) => eprintln!("error: {e}"),
			},
			Self::Pe { pid, path } => {
				let target = match (pid, path) {
					(Some(p), None) => PeTarget::Pid(*p),
					(None, Some(p)) => PeTarget::Path(p.clone()),
					_ => {
						eprintln!("error: exactly one of <PID> or --path must be provided");
						return;
					}
				};
				match platform.inspect_pe(&target) {
					Ok(info) => print_pe_info(&info, format),
					Err(e) => eprintln!("error: {e}"),
				}
			}
			Self::Elf { pid, path } => {
				let target = match (pid, path) {
					(Some(p), None) => ElfTarget::Pid(*p),
					(None, Some(p)) => ElfTarget::Path(p.clone()),
					_ => {
						eprintln!("error: exactly one of <PID> or --path must be provided");
						return;
					}
				};
				match platform.inspect_elf(&target) {
					Ok(info) => print_elf_info(&info, format),
					Err(e) => eprintln!("error: {e}"),
				}
			}
			Self::Token { pid } => match platform.inspect_process_token(*pid) {
				Ok(info) => print_token_info(&info, format),
				Err(e) => eprintln!("error: {e}"),
			},
			Self::Env { pid } => match platform.process_environment(*pid) {
				Ok(vars) => match format {
					OutputFormat::Json => {
						let map: std::collections::BTreeMap<&str, &str> =
							vars.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
						match serde_json::to_string_pretty(&map) {
							Ok(json) => println!("{json}"),
							Err(e) => eprintln!("error serializing JSON: {e}"),
						}
					}
					OutputFormat::Table => {
						println!("{:<40} VALUE", "KEY");
						for (k, v) in &vars {
							println!("{:<40} {}", truncate(k, 40), truncate(v, 80));
						}
					}
				},
				Err(e) => eprintln!("error: {e}"),
			},
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

impl TableDisplay for PrivilegeInfo {
	fn print_header() {
		println!("{:<40} ENABLED", "PRIVILEGE");
	}

	fn print_row(&self) {
		println!("{:<40} {}", self.name, self.enabled);
	}
}

impl TableDisplay for HandleInfo {
	fn print_header() {
		println!("{:<10} {:<15} {:>10} NAME", "HANDLE", "TYPE", "ACCESS");
	}

	fn print_row(&self) {
		println!(
			"{:<10} {:<15} 0x{:08x} {}",
			self.handle_value,
			truncate(&self.object_type, 15),
			self.access_mask,
			self.name.as_deref().unwrap_or(""),
		);
	}
}

impl TableDisplay for PeSection {
	fn print_header() {
		println!(
			"{:<10} {:>12} {:>12} {:>12} FLAGS",
			"NAME", "VADDR", "VSIZE", "RAWSIZE"
		);
	}

	fn print_row(&self) {
		println!(
			"{:<10} 0x{:08x} {:>12} {:>12} {}",
			self.name,
			self.virtual_address,
			self.virtual_size,
			self.raw_size,
			self.characteristics.join(","),
		);
	}
}

impl TableDisplay for PeImport {
	fn print_header() {
		println!("{:<30} FUNCTIONS", "DLL");
	}

	fn print_row(&self) {
		println!(
			"{:<30} {}",
			truncate(&self.dll_name, 30),
			self.functions.len(),
		);
	}
}

impl TableDisplay for PeExport {
	fn print_header() {
		println!("{:<8} {:>10} NAME", "ORDINAL", "RVA");
	}

	fn print_row(&self) {
		println!(
			"{:<8} 0x{:08x} {}",
			self.ordinal,
			self.rva,
			self.name.as_deref().unwrap_or("(ordinal)"),
		);
	}
}

fn print_pe_info(info: &PeInfo, format: OutputFormat) {
	match format {
		OutputFormat::Json => match serde_json::to_string_pretty(info) {
			Ok(json) => println!("{json}"),
			Err(e) => eprintln!("error serializing JSON: {e}"),
		},
		OutputFormat::Table => {
			println!("Machine:        {}", info.machine);
			println!("Characteristics: {}", info.characteristics.join(", "));
			println!("Entry Point:    0x{:x}", info.entry_point);
			println!("Image Base:     0x{:x}", info.image_base);
			println!("Image Size:     0x{:x}", info.image_size);
			println!("Timestamp:      {}", info.timestamp);
			println!("Subsystem:      {}", info.subsystem);
			println!();
			println!("Sections ({}):", info.sections.len());
			if !info.sections.is_empty() {
				PeSection::print_header();
				for s in &info.sections {
					s.print_row();
				}
			}
			println!();
			println!("Imports ({} DLLs):", info.imports.len());
			if !info.imports.is_empty() {
				PeImport::print_header();
				for i in &info.imports {
					i.print_row();
				}
			}
			println!();
			println!("Exports ({}):", info.exports.len());
			if !info.exports.is_empty() {
				PeExport::print_header();
				for e in &info.exports {
					e.print_row();
				}
			}
		}
	}
}

impl TableDisplay for TokenGroup {
	fn print_header() {
		println!("{:<40} {:<50} ATTRIBUTES", "NAME", "SID");
	}

	fn print_row(&self) {
		println!(
			"{:<40} {:<50} {}",
			truncate(&self.name, 40),
			truncate(&self.sid, 50),
			self.attributes.join(","),
		);
	}
}

fn print_token_info(info: &TokenInfo, format: OutputFormat) {
	match format {
		OutputFormat::Json => match serde_json::to_string_pretty(info) {
			Ok(json) => println!("{json}"),
			Err(e) => eprintln!("error serializing JSON: {e}"),
		},
		OutputFormat::Table => {
			println!("PID:              {}", info.pid);
			println!("User:             {}", info.user);
			println!("Integrity:        {}", info.integrity_level);
			println!("Token Type:       {}", info.token_type);
			if let Some(ref imp) = info.impersonation_level {
				println!("Impersonation:    {imp}");
			}
			println!("Elevation Type:   {}", info.elevation_type);
			println!("Is Elevated:      {}", info.is_elevated);
			println!("Is Restricted:    {}", info.is_restricted);
			println!("Session ID:       {}", info.session_id);
			println!();
			println!("Groups ({}):", info.groups.len());
			if !info.groups.is_empty() {
				TokenGroup::print_header();
				for g in &info.groups {
					g.print_row();
				}
			}
			println!();
			println!("Privileges ({}):", info.privileges.len());
			if !info.privileges.is_empty() {
				PrivilegeInfo::print_header();
				for p in &info.privileges {
					p.print_row();
				}
			}
		}
	}
}

impl TableDisplay for ElfSection {
	fn print_header() {
		println!(
			"{:<20} {:<12} {:>12} {:>12} {:>12} FLAGS",
			"NAME", "TYPE", "ADDR", "OFFSET", "SIZE"
		);
	}

	fn print_row(&self) {
		println!(
			"{:<20} {:<12} 0x{:08x} 0x{:08x} {:>12} {}",
			truncate(&self.name, 20),
			self.section_type,
			self.address,
			self.offset,
			self.size,
			self.flags.join(","),
		);
	}
}

impl TableDisplay for ElfSymbol {
	fn print_header() {
		println!(
			"{:<40} {:>12} {:>8} {:<8} {:<8} {:<10} SECTION",
			"NAME", "VALUE", "SIZE", "TYPE", "BIND", "VIS"
		);
	}

	fn print_row(&self) {
		println!(
			"{:<40} 0x{:08x} {:>8} {:<8} {:<8} {:<10} {}",
			truncate(&self.name, 40),
			self.value,
			self.size,
			self.symbol_type,
			self.binding,
			self.visibility,
			self.section.as_deref().unwrap_or(""),
		);
	}
}

fn print_elf_info(info: &ElfInfo, format: OutputFormat) {
	match format {
		OutputFormat::Json => match serde_json::to_string_pretty(info) {
			Ok(json) => println!("{json}"),
			Err(e) => eprintln!("error serializing JSON: {e}"),
		},
		OutputFormat::Table => {
			println!("Class:          {}", info.class);
			println!("Endianness:     {}", info.endianness);
			println!("OS/ABI:         {}", info.os_abi);
			println!("Type:           {}", info.elf_type);
			println!("Machine:        {}", info.machine);
			println!("Entry Point:    0x{:x}", info.entry_point);
			if let Some(ref interp) = info.interpreter {
				println!("Interpreter:    {interp}");
			}
			println!();
			println!("Sections ({}):", info.sections.len());
			if !info.sections.is_empty() {
				ElfSection::print_header();
				for s in &info.sections {
					s.print_row();
				}
			}
			println!();
			println!("Dynamic Libraries ({}):", info.dynamic_libs.len());
			for lib in &info.dynamic_libs {
				println!("  {lib}");
			}
			println!();
			println!("Dynamic Symbols ({}):", info.symbols.len());
			if !info.symbols.is_empty() {
				ElfSymbol::print_header();
				for s in &info.symbols {
					s.print_row();
				}
			}
		}
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
