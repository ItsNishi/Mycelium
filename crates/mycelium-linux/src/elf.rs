//! ELF binary parsing using goblin.

use mycelium_core::error::{MyceliumError, Result};
use mycelium_core::types::{ElfInfo, ElfSection, ElfSymbol, ElfTarget};
use std::fs;

/// Maximum sections to return (safety limit).
const MAX_SECTIONS: usize = 256;

/// Maximum symbols to return (safety limit).
const MAX_SYMBOLS: usize = 65536;

/// Maximum dynamic library entries to return.
const MAX_DYNAMIC_LIBS: usize = 512;

/// Maximum file size to read (64 MiB).
const MAX_ELF_READ: usize = 64 * 1024 * 1024;

/// Parse ELF headers from a file path or a running process.
pub fn inspect_elf(target: &ElfTarget) -> Result<ElfInfo> {
	let path = match target {
		ElfTarget::Path(p) => p.clone(),
		ElfTarget::Pid(pid) => {
			let exe_link = format!("/proc/{pid}/exe");
			fs::read_link(&exe_link)
				.map_err(|e| match e.kind() {
					std::io::ErrorKind::PermissionDenied => {
						MyceliumError::PermissionDenied(format!("cannot read {exe_link}"))
					}
					std::io::ErrorKind::NotFound => {
						MyceliumError::NotFound(format!("process {pid}"))
					}
					_ => MyceliumError::IoError(e),
				})?
				.to_string_lossy()
				.to_string()
		}
	};

	let data = read_elf_file(&path)?;
	parse_elf(&data, &path)
}

fn read_elf_file(path: &str) -> Result<Vec<u8>> {
	let metadata = fs::metadata(path).map_err(|e| match e.kind() {
		std::io::ErrorKind::NotFound => MyceliumError::NotFound(format!("file not found: {path}")),
		std::io::ErrorKind::PermissionDenied => {
			MyceliumError::PermissionDenied(format!("cannot read {path}"))
		}
		_ => MyceliumError::IoError(e),
	})?;

	if metadata.len() as usize > MAX_ELF_READ {
		return Err(MyceliumError::ParseError(format!(
			"file too large: {} bytes (max {MAX_ELF_READ})",
			metadata.len()
		)));
	}

	fs::read(path).map_err(MyceliumError::IoError)
}

fn parse_elf(data: &[u8], path: &str) -> Result<ElfInfo> {
	let elf = goblin::elf::Elf::parse(data)
		.map_err(|e| MyceliumError::ParseError(format!("not a valid ELF file ({path}): {e}")))?;

	let header = &elf.header;

	let class = match header.e_ident[goblin::elf::header::EI_CLASS] {
		1 => "ELF32",
		2 => "ELF64",
		_ => "unknown",
	}
	.to_string();

	let endianness = match header.e_ident[goblin::elf::header::EI_DATA] {
		1 => "little",
		2 => "big",
		_ => "unknown",
	}
	.to_string();

	let os_abi = match header.e_ident[goblin::elf::header::EI_OSABI] {
		0 => "SYSV",
		3 => "GNU",
		6 => "Solaris",
		9 => "FreeBSD",
		12 => "OpenBSD",
		_ => "other",
	}
	.to_string();

	let elf_type = match header.e_type {
		goblin::elf::header::ET_REL => "relocatable",
		goblin::elf::header::ET_EXEC => "executable",
		goblin::elf::header::ET_DYN => "shared object",
		goblin::elf::header::ET_CORE => "core",
		_ => "unknown",
	}
	.to_string();

	let machine = machine_name(header.e_machine);
	let entry_point = header.e_entry;
	let interpreter = elf.interpreter.map(|s| s.to_string());

	let sections = parse_sections(&elf);
	let dynamic_libs = parse_dynamic_libs(&elf);
	let symbols = parse_dynamic_symbols(&elf);

	Ok(ElfInfo {
		class,
		endianness,
		os_abi,
		elf_type,
		machine,
		entry_point,
		interpreter,
		sections,
		dynamic_libs,
		symbols,
	})
}

fn machine_name(machine: u16) -> String {
	match machine {
		goblin::elf::header::EM_386 => "x86",
		goblin::elf::header::EM_X86_64 => "x86_64",
		goblin::elf::header::EM_ARM => "ARM",
		goblin::elf::header::EM_AARCH64 => "AArch64",
		goblin::elf::header::EM_MIPS => "MIPS",
		goblin::elf::header::EM_PPC => "PowerPC",
		goblin::elf::header::EM_PPC64 => "PowerPC64",
		goblin::elf::header::EM_RISCV => "RISC-V",
		goblin::elf::header::EM_S390 => "s390x",
		other => return format!("unknown({other})"),
	}
	.to_string()
}

fn section_type_name(sh_type: u32) -> String {
	use goblin::elf::section_header::*;
	match sh_type {
		SHT_NULL => "NULL",
		SHT_PROGBITS => "PROGBITS",
		SHT_SYMTAB => "SYMTAB",
		SHT_STRTAB => "STRTAB",
		SHT_RELA => "RELA",
		SHT_HASH => "HASH",
		SHT_DYNAMIC => "DYNAMIC",
		SHT_NOTE => "NOTE",
		SHT_NOBITS => "NOBITS",
		SHT_REL => "REL",
		SHT_DYNSYM => "DYNSYM",
		SHT_INIT_ARRAY => "INIT_ARRAY",
		SHT_FINI_ARRAY => "FINI_ARRAY",
		SHT_GNU_HASH => "GNU_HASH",
		SHT_GNU_VERSYM => "GNU_VERSYM",
		SHT_GNU_VERDEF => "GNU_VERDEF",
		SHT_GNU_VERNEED => "GNU_VERNEED",
		_ => return format!("0x{sh_type:x}"),
	}
	.to_string()
}

fn section_flags(sh_flags: u64) -> Vec<String> {
	use goblin::elf::section_header::*;
	let mut flags = Vec::new();
	if sh_flags & SHF_WRITE as u64 != 0 {
		flags.push("WRITE".to_string());
	}
	if sh_flags & SHF_ALLOC as u64 != 0 {
		flags.push("ALLOC".to_string());
	}
	if sh_flags & SHF_EXECINSTR as u64 != 0 {
		flags.push("EXECINSTR".to_string());
	}
	flags
}

fn parse_sections(elf: &goblin::elf::Elf) -> Vec<ElfSection> {
	elf.section_headers
		.iter()
		.take(MAX_SECTIONS)
		.map(|sh| {
			let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
			ElfSection {
				name,
				section_type: section_type_name(sh.sh_type),
				address: sh.sh_addr,
				offset: sh.sh_offset,
				size: sh.sh_size,
				flags: section_flags(sh.sh_flags),
			}
		})
		.collect()
}

fn parse_dynamic_libs(elf: &goblin::elf::Elf) -> Vec<String> {
	elf.libraries
		.iter()
		.take(MAX_DYNAMIC_LIBS)
		.map(|s| s.to_string())
		.collect()
}

fn symbol_type_name(stype: u8) -> &'static str {
	use goblin::elf::sym::*;
	match stype {
		STT_NOTYPE => "NOTYPE",
		STT_OBJECT => "OBJECT",
		STT_FUNC => "FUNC",
		STT_SECTION => "SECTION",
		STT_FILE => "FILE",
		STT_COMMON => "COMMON",
		STT_TLS => "TLS",
		STT_GNU_IFUNC => "IFUNC",
		_ => "unknown",
	}
}

fn symbol_binding_name(sbind: u8) -> &'static str {
	use goblin::elf::sym::*;
	match sbind {
		STB_LOCAL => "LOCAL",
		STB_GLOBAL => "GLOBAL",
		STB_WEAK => "WEAK",
		STB_GNU_UNIQUE => "UNIQUE",
		_ => "unknown",
	}
}

fn symbol_visibility_name(st_other: u8) -> &'static str {
	use goblin::elf::sym::*;
	match st_other & 0x3 {
		STV_DEFAULT => "DEFAULT",
		STV_INTERNAL => "INTERNAL",
		STV_HIDDEN => "HIDDEN",
		STV_PROTECTED => "PROTECTED",
		_ => "unknown",
	}
}

fn parse_dynamic_symbols(elf: &goblin::elf::Elf) -> Vec<ElfSymbol> {
	elf.dynsyms
		.iter()
		.take(MAX_SYMBOLS)
		.filter_map(|sym| {
			let name = elf.dynstrtab.get_at(sym.st_name)?.to_string();
			if name.is_empty() {
				return None;
			}

			let section = if sym.st_shndx == goblin::elf::section_header::SHN_UNDEF as usize {
				Some("UND".to_string())
			} else if sym.st_shndx < elf.section_headers.len() {
				let sh = &elf.section_headers[sym.st_shndx];
				Some(elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string())
			} else {
				None
			};

			Some(ElfSymbol {
				name,
				value: sym.st_value,
				size: sym.st_size,
				symbol_type: symbol_type_name(sym.st_type()).to_string(),
				binding: symbol_binding_name(sym.st_bind()).to_string(),
				visibility: symbol_visibility_name(sym.st_other).to_string(),
				section,
			})
		})
		.collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_inspect_self_exe() {
		let info = inspect_elf(&ElfTarget::Path("/proc/self/exe".to_string())).unwrap();
		assert_eq!(info.class, "ELF64");
		assert_eq!(info.endianness, "little");
		assert!(!info.machine.is_empty());
		assert!(info.entry_point > 0);
		assert!(!info.sections.is_empty());
	}

	#[test]
	fn test_inspect_self_pid() {
		let pid = std::process::id();
		let info = inspect_elf(&ElfTarget::Pid(pid)).unwrap();
		assert_eq!(info.class, "ELF64");
		assert!(!info.sections.is_empty());
	}

	#[test]
	fn test_inspect_nonexistent_file() {
		let result = inspect_elf(&ElfTarget::Path("/nonexistent/binary".to_string()));
		assert!(result.is_err());
	}

	#[test]
	fn test_inspect_not_elf() {
		// /etc/passwd is not an ELF file
		let result = inspect_elf(&ElfTarget::Path("/etc/passwd".to_string()));
		assert!(result.is_err());
	}

	#[test]
	fn test_sections_have_names() {
		let info = inspect_elf(&ElfTarget::Path("/proc/self/exe".to_string())).unwrap();
		// Every ELF has at least a .text section
		let has_text = info.sections.iter().any(|s| s.name == ".text");
		assert!(has_text, "expected .text section");
	}

	#[test]
	fn test_machine_name() {
		assert_eq!(machine_name(goblin::elf::header::EM_X86_64), "x86_64");
		assert_eq!(machine_name(goblin::elf::header::EM_AARCH64), "AArch64");
		assert_eq!(machine_name(0xFFFF), "unknown(65535)");
	}
}
