use clap::Subcommand;
use mycelium_core::platform::Platform;
use mycelium_core::types::{MemoryInfo, MemoryRegion, ProcessMemory};

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
	/// List virtual memory regions for a process
	Maps {
		/// Process ID
		pid: u32,
	},
	/// Read raw bytes from a process's virtual memory
	Read {
		/// Process ID
		pid: u32,
		/// Start address (decimal or 0x-prefixed hex)
		address: String,
		/// Number of bytes to read
		size: usize,
	},
	/// Write raw bytes to a process's virtual memory
	Write {
		/// Process ID
		pid: u32,
		/// Start address (decimal or 0x-prefixed hex)
		address: String,
		/// Hex-encoded data to write (e.g. "4141ff00")
		hex_data: String,
	},
}

impl MemoryCmd {
	pub fn run(&self, platform: &dyn Platform, format: OutputFormat, dry_run: bool) {
		match self {
			Self::Info => match platform.memory_info() {
				Ok(info) => print_output(&info, format),
				Err(e) => eprintln!("error: {e}"),
			},
			Self::Process { pid } => match platform.process_memory(*pid) {
				Ok(mem) => print_output(&mem, format),
				Err(e) => eprintln!("error: {e}"),
			},
			Self::Maps { pid } => {
				if dry_run {
					println!("[dry-run] memory maps would read /proc/{pid}/maps");
					return;
				}
				match platform.process_memory_maps(*pid) {
					Ok(regions) => print_list(&regions, format),
					Err(e) => eprintln!("error: {e}"),
				}
			}
			Self::Read { pid, address, size } => {
				if dry_run {
					println!("[dry-run] memory read would read {size} bytes from pid {pid} at {address}");
					return;
				}
				let addr = match parse_address(address) {
					Ok(a) => a,
					Err(e) => {
						eprintln!("error: {e}");
						return;
					}
				};
				match platform.read_process_memory(*pid, addr, *size) {
					Ok(data) => print_hex_dump(addr, &data),
					Err(e) => eprintln!("error: {e}"),
				}
			}
			Self::Write { pid, address, hex_data } => {
				if dry_run {
					println!(
						"[dry-run] memory write would write {} bytes to pid {pid} at {address}",
						hex_data.len() / 2
					);
					return;
				}
				let addr = match parse_address(address) {
					Ok(a) => a,
					Err(e) => {
						eprintln!("error: {e}");
						return;
					}
				};
				let data = match hex_decode(hex_data) {
					Ok(d) => d,
					Err(e) => {
						eprintln!("error: {e}");
						return;
					}
				};
				match platform.write_process_memory(*pid, addr, &data) {
					Ok(written) => println!("{written} bytes written to pid {pid} at {addr:#x}"),
					Err(e) => eprintln!("error: {e}"),
				}
			}
		}
	}
}

/// Parse an address string that may be decimal or 0x-prefixed hex.
fn parse_address(s: &str) -> Result<u64, String> {
	if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
		u64::from_str_radix(hex, 16).map_err(|e| format!("invalid hex address '{s}': {e}"))
	} else {
		s.parse::<u64>().map_err(|e| format!("invalid address '{s}': {e}"))
	}
}

/// Decode a hex string into bytes.
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
	let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
	if !s.len().is_multiple_of(2) {
		return Err(format!("hex string has odd length: {}", s.len()));
	}
	(0..s.len())
		.step_by(2)
		.map(|i| {
			u8::from_str_radix(&s[i..i + 2], 16)
				.map_err(|e| format!("invalid hex at position {i}: {e}"))
		})
		.collect()
}

/// Print a hex dump in the standard format (16 bytes per line with ASCII sidebar).
fn print_hex_dump(base_address: u64, data: &[u8]) {
	for (i, chunk) in data.chunks(16).enumerate() {
		let addr = base_address + (i * 16) as u64;

		// Address
		print!("{addr:016x}  ");

		// Hex bytes (two groups of 8)
		for (j, byte) in chunk.iter().enumerate() {
			if j == 8 {
				print!(" ");
			}
			print!("{byte:02x} ");
		}

		// Pad if last line is short
		let padding = 16 - chunk.len();
		for j in 0..padding {
			if chunk.len() + j == 8 {
				print!(" ");
			}
			print!("   ");
		}

		// ASCII representation
		print!(" |");
		for byte in chunk {
			if byte.is_ascii_graphic() || *byte == b' ' {
				print!("{}", *byte as char);
			} else {
				print!(".");
			}
		}
		// Pad ASCII if short
		for _ in 0..padding {
			print!(" ");
		}
		println!("|");
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

impl TableDisplay for MemoryRegion {
	fn print_header() {
		println!(
			"{:<18} {:<18} {:<6} {:>10} {:<8} {:>10} PATHNAME",
			"START", "END", "PERMS", "OFFSET", "DEV", "INODE"
		);
	}

	fn print_row(&self) {
		println!(
			"{:<18} {:<18} {:<6} {:>10} {:<8} {:>10} {}",
			format!("{:#x}", self.start_address),
			format!("{:#x}", self.end_address),
			self.permissions,
			format!("{:#x}", self.offset),
			self.device,
			self.inode,
			self.pathname.as_deref().unwrap_or(""),
		);
	}
}
