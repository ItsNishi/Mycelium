use clap::Subcommand;
use mycelium_core::platform::Platform;
use mycelium_core::types::{
	MemoryInfo, MemoryRegion, MemorySearchOptions, ProcessMemory, SearchPattern,
};

/// Decode a hex string that may contain `??` wildcard bytes.
///
/// Returns `(bytes, mask)`. If no wildcards are present, mask is `None`.
fn hex_decode_masked(s: &str) -> Result<(Vec<u8>, Option<Vec<u8>>), String> {
	let s = s
		.strip_prefix("0x")
		.or_else(|| s.strip_prefix("0X"))
		.unwrap_or(s);
	if !s.len().is_multiple_of(2) {
		return Err(format!("hex string has odd length: {}", s.len()));
	}

	let mut bytes = Vec::with_capacity(s.len() / 2);
	let mut mask = Vec::with_capacity(s.len() / 2);
	let mut has_wildcards = false;

	for i in (0..s.len()).step_by(2) {
		let pair = &s[i..i + 2];
		if pair == "??" {
			bytes.push(0x00);
			mask.push(0x00);
			has_wildcards = true;
		} else {
			let byte = u8::from_str_radix(pair, 16)
				.map_err(|e| format!("invalid hex at position {i}: {e}"))?;
			bytes.push(byte);
			mask.push(0xFF);
		}
	}

	if has_wildcards {
		Ok((bytes, Some(mask)))
	} else {
		Ok((bytes, None))
	}
}

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
	/// Search process memory for byte patterns or strings
	Search {
		/// Process ID
		pid: u32,
		/// Hex pattern with optional ?? wildcards (e.g. "4d5a??00", "488B????8905")
		#[arg(long)]
		hex: Option<String>,
		/// UTF-8 string pattern
		#[arg(long)]
		utf8: Option<String>,
		/// UTF-16 string pattern
		#[arg(long)]
		utf16: Option<String>,
		/// Max results
		#[arg(long, default_value = "100")]
		max_matches: usize,
		/// Permission filter (e.g. "rw")
		#[arg(long)]
		perms: Option<String>,
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
					println!(
						"[dry-run] memory read would read {size} bytes from pid {pid} at {address}"
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
				match platform.read_process_memory(*pid, addr, *size) {
					Ok(data) => print_hex_dump(addr, &data),
					Err(e) => eprintln!("error: {e}"),
				}
			}
			Self::Write {
				pid,
				address,
				hex_data,
			} => {
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
			Self::Search {
				pid,
				hex,
				utf8,
				utf16,
				max_matches,
				perms,
			} => {
				if dry_run {
					println!("[dry-run] memory search would scan pid {pid}");
					return;
				}

				let pattern_count =
					hex.is_some() as u8 + utf8.is_some() as u8 + utf16.is_some() as u8;
				if pattern_count != 1 {
					eprintln!("error: exactly one of --hex, --utf8, or --utf16 must be provided");
					return;
				}

				let pattern = if let Some(h) = hex {
					match hex_decode_masked(h) {
						Ok((bytes, None)) => SearchPattern::Bytes(bytes),
						Ok((pattern, Some(mask))) => SearchPattern::MaskedBytes { pattern, mask },
						Err(e) => {
							eprintln!("error: {e}");
							return;
						}
					}
				} else if let Some(u) = utf8 {
					SearchPattern::Utf8(u.clone())
				} else if let Some(u) = utf16 {
					SearchPattern::Utf16(u.clone())
				} else {
					unreachable!()
				};

				let options = MemorySearchOptions {
					max_matches: *max_matches,
					context_size: 32,
					permissions_filter: perms.clone().unwrap_or_default(),
				};

				match platform.search_process_memory(*pid, &pattern, &options) {
					Ok(matches) => {
						if matches.is_empty() {
							println!("no matches found");
						} else {
							println!("{} match(es) found:\n", matches.len());
							for m in &matches {
								println!(
									"  {:#018x}  region={:#x} perms={} {}",
									m.address,
									m.region_start,
									m.region_permissions,
									m.region_pathname.as_deref().unwrap_or(""),
								);
								if !m.context_bytes.is_empty() {
									let ctx_start = m
										.address
										.saturating_sub((m.context_bytes.len() / 2) as u64);
									print_hex_dump(ctx_start, &m.context_bytes);
								}
								println!();
							}
						}
					}
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
		s.parse::<u64>()
			.map_err(|e| format!("invalid address '{s}': {e}"))
	}
}

/// Decode a hex string into bytes.
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
	let s = s
		.strip_prefix("0x")
		.or_else(|| s.strip_prefix("0X"))
		.unwrap_or(s);
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

#[cfg(test)]
mod tests {
	use super::*;

	// parse_address tests

	#[test]
	fn test_parse_address_decimal() {
		assert_eq!(parse_address("12345").unwrap(), 12345);
	}

	#[test]
	fn test_parse_address_hex_lowercase() {
		assert_eq!(parse_address("0x1a2b").unwrap(), 0x1a2b);
	}

	#[test]
	fn test_parse_address_hex_uppercase() {
		assert_eq!(parse_address("0X1A2B").unwrap(), 0x1a2b);
	}

	#[test]
	fn test_parse_address_invalid() {
		assert!(parse_address("not_a_number").is_err());
	}

	// hex_decode tests

	#[test]
	fn test_hex_decode_normal() {
		assert_eq!(
			hex_decode("4141ff00").unwrap(),
			vec![0x41, 0x41, 0xff, 0x00]
		);
	}

	#[test]
	fn test_hex_decode_0x_prefix() {
		assert_eq!(hex_decode("0x4141").unwrap(), vec![0x41, 0x41]);
	}

	#[test]
	fn test_hex_decode_0x_uppercase_prefix() {
		assert_eq!(hex_decode("0X4141").unwrap(), vec![0x41, 0x41]);
	}

	#[test]
	fn test_hex_decode_odd_length() {
		assert!(hex_decode("414").is_err());
	}

	#[test]
	fn test_hex_decode_invalid_chars() {
		assert!(hex_decode("gg00").is_err());
	}

	#[test]
	fn test_hex_decode_empty() {
		assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());
	}

	// hex_decode_masked tests

	#[test]
	fn test_hex_decode_masked_no_wildcards() {
		let (bytes, mask) = hex_decode_masked("4141ff00").unwrap();
		assert_eq!(bytes, vec![0x41, 0x41, 0xff, 0x00]);
		assert!(mask.is_none());
	}

	#[test]
	fn test_hex_decode_masked_with_wildcards() {
		let (bytes, mask) = hex_decode_masked("48??8B??").unwrap();
		assert_eq!(bytes, vec![0x48, 0x00, 0x8B, 0x00]);
		assert_eq!(mask.unwrap(), vec![0xFF, 0x00, 0xFF, 0x00]);
	}

	#[test]
	fn test_hex_decode_masked_0x_prefix() {
		let (bytes, mask) = hex_decode_masked("0x48??").unwrap();
		assert_eq!(bytes, vec![0x48, 0x00]);
		assert_eq!(mask.unwrap(), vec![0xFF, 0x00]);
	}

	#[test]
	fn test_hex_decode_masked_odd_length() {
		assert!(hex_decode_masked("4?1").is_err());
	}

	#[test]
	fn test_hex_decode_masked_invalid_chars() {
		assert!(hex_decode_masked("zz00").is_err());
	}
}
