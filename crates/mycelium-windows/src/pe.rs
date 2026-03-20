//! PE header parsing — manual parser for PE32/PE32+ executables.

use std::mem;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::ProcessStatus::{EnumProcessModules, GetModuleInformation, MODULEINFO};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

use mycelium_core::error::{MyceliumError, Result};
use mycelium_core::types::{PeExport, PeImport, PeInfo, PeSection, PeTarget};

// ---------------------------------------------------------------------------
// Safety limits
// ---------------------------------------------------------------------------

const MAX_SECTIONS: usize = 96;
const MAX_IMPORTS: usize = 4096;
const MAX_IMPORT_FUNCTIONS: usize = 8192;
const MAX_EXPORTS: usize = 65536;
const MAX_PE_READ: usize = 4 * 1024 * 1024; // 4 MiB for file reads

// ---------------------------------------------------------------------------
// RAII guard for Windows HANDLE
// ---------------------------------------------------------------------------

struct SafeHandle(HANDLE);

impl Drop for SafeHandle {
	fn drop(&mut self) {
		unsafe {
			let _ = CloseHandle(self.0);
		}
	}
}

impl SafeHandle {
	fn open_process(
		access: windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS,
		pid: u32,
	) -> std::result::Result<Self, windows::core::Error> {
		let handle = unsafe { OpenProcess(access, false, pid) }?;
		Ok(Self(handle))
	}

	fn raw(&self) -> HANDLE {
		self.0
	}
}

// ---------------------------------------------------------------------------
// Little-endian readers
// ---------------------------------------------------------------------------

fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
	let end = offset.checked_add(2).ok_or_else(|| {
		MyceliumError::ParseError(format!("u16 read overflow at offset {offset}"))
	})?;
	if end > data.len() {
		return Err(MyceliumError::ParseError(format!(
			"u16 read at offset {offset} exceeds data length {}",
			data.len()
		)));
	}
	Ok(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
	let end = offset.checked_add(4).ok_or_else(|| {
		MyceliumError::ParseError(format!("u32 read overflow at offset {offset}"))
	})?;
	if end > data.len() {
		return Err(MyceliumError::ParseError(format!(
			"u32 read at offset {offset} exceeds data length {}",
			data.len()
		)));
	}
	Ok(u32::from_le_bytes([
		data[offset],
		data[offset + 1],
		data[offset + 2],
		data[offset + 3],
	]))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64> {
	let end = offset.checked_add(8).ok_or_else(|| {
		MyceliumError::ParseError(format!("u64 read overflow at offset {offset}"))
	})?;
	if end > data.len() {
		return Err(MyceliumError::ParseError(format!(
			"u64 read at offset {offset} exceeds data length {}",
			data.len()
		)));
	}
	Ok(u64::from_le_bytes([
		data[offset],
		data[offset + 1],
		data[offset + 2],
		data[offset + 3],
		data[offset + 4],
		data[offset + 5],
		data[offset + 6],
		data[offset + 7],
	]))
}

// ---------------------------------------------------------------------------
// Internal section header (used during parsing)
// ---------------------------------------------------------------------------

struct SectionHeader {
	name: String,
	virtual_address: u32,
	virtual_size: u32,
	size_of_raw_data: u32,
	pointer_to_raw_data: u32,
	characteristics: u32,
}

// ---------------------------------------------------------------------------
// PeReader trait + implementations
// ---------------------------------------------------------------------------

trait PeReader {
	fn read_at(&self, offset: usize, size: usize) -> Result<Vec<u8>>;
}

/// Reads PE data from a file already loaded into memory.
struct FilePeReader {
	data: Vec<u8>,
}

impl PeReader for FilePeReader {
	fn read_at(&self, offset: usize, size: usize) -> Result<Vec<u8>> {
		let end = offset.checked_add(size).ok_or_else(|| {
			MyceliumError::ParseError(format!("read overflow at offset {offset} size {size}"))
		})?;
		if end > self.data.len() {
			return Err(MyceliumError::ParseError(format!(
				"read at offset {offset} size {size} exceeds file length {}",
				self.data.len()
			)));
		}
		Ok(self.data[offset..end].to_vec())
	}
}

/// Reads PE data from a live process via `ReadProcessMemory`.
struct ProcessPeReader {
	handle: SafeHandle,
	base_address: usize,
}

impl PeReader for ProcessPeReader {
	fn read_at(&self, offset: usize, size: usize) -> Result<Vec<u8>> {
		let address = self.base_address.checked_add(offset).ok_or_else(|| {
			MyceliumError::ParseError(format!(
				"address overflow: base 0x{:X} + offset 0x{:X}",
				self.base_address, offset
			))
		})?;

		let mut buffer = vec![0u8; size];
		let mut bytes_read: usize = 0;

		unsafe {
			ReadProcessMemory(
				self.handle.raw(),
				address as *const _,
				buffer.as_mut_ptr() as *mut _,
				size,
				Some(&mut bytes_read),
			)
		}
		.map_err(|e| MyceliumError::OsError {
			code: e.code().0,
			message: format!("ReadProcessMemory at 0x{address:X} size {size} failed: {e}"),
		})?;

		if bytes_read < size {
			return Err(MyceliumError::ParseError(format!(
				"short read: requested {size} bytes at 0x{address:X}, got {bytes_read}"
			)));
		}

		Ok(buffer)
	}
}

// ---------------------------------------------------------------------------
// RVA-to-file-offset conversion
// ---------------------------------------------------------------------------

fn rva_to_file_offset(rva: u32, sections: &[SectionHeader]) -> Option<usize> {
	for s in sections {
		if rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size {
			return Some((rva - s.virtual_address + s.pointer_to_raw_data) as usize);
		}
	}
	None
}

// ---------------------------------------------------------------------------
// Read a null-terminated ASCII string from a reader
// ---------------------------------------------------------------------------

fn read_cstring(reader: &dyn PeReader, offset: usize, max_len: usize) -> Result<String> {
	let data = reader.read_at(offset, max_len)?;
	let nul_pos = data.iter().position(|&b| b == 0).unwrap_or(data.len());
	String::from_utf8(data[..nul_pos].to_vec())
		.map_err(|e| MyceliumError::ParseError(format!("invalid UTF-8 in PE string: {e}")))
}

// ---------------------------------------------------------------------------
// Decode characteristic flags
// ---------------------------------------------------------------------------

fn decode_coff_characteristics(chars: u16) -> Vec<String> {
	let mut flags = Vec::new();
	if chars & 0x0002 != 0 {
		flags.push("EXECUTABLE".to_string());
	}
	if chars & 0x0020 != 0 {
		flags.push("LARGE_ADDRESS_AWARE".to_string());
	}
	if chars & 0x2000 != 0 {
		flags.push("DLL".to_string());
	}
	flags
}

fn decode_section_characteristics(chars: u32) -> Vec<String> {
	let mut flags = Vec::new();
	if chars & 0x0000_0020 != 0 {
		flags.push("CODE".to_string());
	}
	if chars & 0x2000_0000 != 0 {
		flags.push("EXECUTE".to_string());
	}
	if chars & 0x4000_0000 != 0 {
		flags.push("READ".to_string());
	}
	if chars & 0x8000_0000 != 0 {
		flags.push("WRITE".to_string());
	}
	flags
}

fn machine_to_string(machine: u16) -> String {
	match machine {
		0x014C => "x86".to_string(),
		0x8664 => "x64".to_string(),
		0xAA64 => "ARM64".to_string(),
		other => format!("unknown(0x{other:04X})"),
	}
}

fn subsystem_to_string(subsystem: u16) -> String {
	match subsystem {
		1 => "Native".to_string(),
		2 => "GUI".to_string(),
		3 => "Console".to_string(),
		other => format!("unknown({other})"),
	}
}

// ---------------------------------------------------------------------------
// Core PE parser
// ---------------------------------------------------------------------------

/// Whether we are reading from a file (RVAs need section-based translation)
/// or from a process (RVAs are direct offsets from base).
enum ReaderKind {
	File,
	Process,
}

fn resolve_rva(rva: u32, kind: &ReaderKind, sections: &[SectionHeader]) -> Option<usize> {
	match kind {
		ReaderKind::File => rva_to_file_offset(rva, sections),
		ReaderKind::Process => Some(rva as usize),
	}
}

fn parse_pe(reader: &dyn PeReader, kind: &ReaderKind) -> Result<PeInfo> {
	// 1. DOS header — first 64 bytes
	let dos_header = reader.read_at(0, 64)?;

	if dos_header[0] != b'M' || dos_header[1] != b'Z' {
		return Err(MyceliumError::ParseError(
			"invalid DOS signature: expected MZ".to_string(),
		));
	}

	// 2. e_lfanew — offset to PE signature
	let e_lfanew = read_u32(&dos_header, 0x3C)? as usize;

	// 3. PE signature
	let pe_sig = reader.read_at(e_lfanew, 4)?;
	if pe_sig != [b'P', b'E', 0, 0] {
		return Err(MyceliumError::ParseError(
			"invalid PE signature: expected PE\\0\\0".to_string(),
		));
	}

	// 4. COFF header (20 bytes immediately after PE signature)
	let coff_offset = e_lfanew + 4;
	let coff = reader.read_at(coff_offset, 20)?;

	let machine = read_u16(&coff, 0)?;
	let number_of_sections = read_u16(&coff, 2)? as usize;
	let timestamp = read_u32(&coff, 4)? as u64;
	let size_of_optional_header = read_u16(&coff, 16)? as usize;
	let coff_characteristics = read_u16(&coff, 18)?;

	if number_of_sections > MAX_SECTIONS {
		return Err(MyceliumError::ParseError(format!(
			"too many sections: {number_of_sections} (max {MAX_SECTIONS})"
		)));
	}

	// 5. Optional header
	let opt_offset = coff_offset + 20;
	if size_of_optional_header < 2 {
		return Err(MyceliumError::ParseError(
			"optional header too small".to_string(),
		));
	}
	let opt_header = reader.read_at(opt_offset, size_of_optional_header)?;

	let magic = read_u16(&opt_header, 0)?;
	let is_pe32_plus = match magic {
		0x10B => false, // PE32
		0x20B => true,  // PE32+
		_ => {
			return Err(MyceliumError::ParseError(format!(
				"unknown optional header magic: 0x{magic:04X}"
			)));
		}
	};

	let entry_point = read_u32(&opt_header, 16)? as u64;

	let image_base = if is_pe32_plus {
		read_u64(&opt_header, 24)?
	} else {
		read_u32(&opt_header, 28)? as u64
	};

	let image_size = read_u32(&opt_header, 56)?;

	let subsystem = read_u16(&opt_header, 68)?;

	let number_of_rva_and_sizes_offset = if is_pe32_plus { 108 } else { 92 };
	let number_of_rva_and_sizes = if number_of_rva_and_sizes_offset + 4 <= opt_header.len() {
		read_u32(&opt_header, number_of_rva_and_sizes_offset)? as usize
	} else {
		0
	};

	// Data directory starts right after NumberOfRvaAndSizes
	let data_dir_offset = number_of_rva_and_sizes_offset + 4;

	// Each data directory entry is 8 bytes: RVA (u32) + Size (u32)
	let read_data_dir = |index: usize| -> Result<(u32, u32)> {
		if index >= number_of_rva_and_sizes {
			return Ok((0, 0));
		}
		let off = data_dir_offset + index * 8;
		if off + 8 > opt_header.len() {
			return Ok((0, 0));
		}
		let rva = read_u32(&opt_header, off)?;
		let size = read_u32(&opt_header, off + 4)?;
		Ok((rva, size))
	};

	let (export_rva, export_size) = read_data_dir(0)?;
	let (import_rva, import_size) = read_data_dir(1)?;

	// 6. Section headers (40 bytes each, starting after optional header)
	let sections_offset = opt_offset + size_of_optional_header;
	let sections_data = reader.read_at(sections_offset, number_of_sections * 40)?;

	let mut sections = Vec::with_capacity(number_of_sections);

	for i in 0..number_of_sections {
		let base = i * 40;

		// Name: 8 bytes, null-terminated
		let name_bytes = &sections_data[base..base + 8];
		let nul_pos = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
		let name = String::from_utf8_lossy(&name_bytes[..nul_pos]).to_string();

		let virtual_size = read_u32(&sections_data, base + 8)?;
		let virtual_address = read_u32(&sections_data, base + 12)?;
		let size_of_raw_data = read_u32(&sections_data, base + 16)?;
		let pointer_to_raw_data = read_u32(&sections_data, base + 20)?;
		let characteristics = read_u32(&sections_data, base + 36)?;

		sections.push(SectionHeader {
			name,
			virtual_address,
			virtual_size,
			size_of_raw_data,
			pointer_to_raw_data,
			characteristics,
		});
	}

	// Build PeSection output
	let pe_sections: Vec<PeSection> = sections
		.iter()
		.map(|s| PeSection {
			name: s.name.clone(),
			virtual_address: s.virtual_address as u64,
			virtual_size: s.virtual_size,
			raw_size: s.size_of_raw_data,
			characteristics: decode_section_characteristics(s.characteristics),
		})
		.collect();

	// 7. Parse imports
	let imports = if import_rva != 0 && import_size != 0 {
		parse_imports(
			reader,
			import_rva,
			import_size,
			&sections,
			kind,
			is_pe32_plus,
		)?
	} else {
		Vec::new()
	};

	// 8. Parse exports
	let exports = if export_rva != 0 && export_size != 0 {
		parse_exports(reader, export_rva, export_size, &sections, kind)?
	} else {
		Vec::new()
	};

	Ok(PeInfo {
		machine: machine_to_string(machine),
		characteristics: decode_coff_characteristics(coff_characteristics),
		entry_point,
		image_base,
		image_size,
		timestamp,
		subsystem: subsystem_to_string(subsystem),
		sections: pe_sections,
		imports,
		exports,
	})
}

// ---------------------------------------------------------------------------
// Import parsing
// ---------------------------------------------------------------------------

fn parse_imports(
	reader: &dyn PeReader,
	import_rva: u32,
	import_size: u32,
	sections: &[SectionHeader],
	kind: &ReaderKind,
	is_pe32_plus: bool,
) -> Result<Vec<PeImport>> {
	let import_offset = resolve_rva(import_rva, kind, sections).ok_or_else(|| {
		MyceliumError::ParseError("cannot resolve import directory RVA".to_string())
	})?;

	// Each IMAGE_IMPORT_DESCRIPTOR is 20 bytes. The table is null-terminated
	// (all-zero entry). We bound by both import_size and MAX_IMPORTS.
	let max_descriptors = (import_size as usize / 20).min(MAX_IMPORTS);
	let desc_data = reader.read_at(import_offset, max_descriptors * 20)?;

	let mut imports = Vec::new();
	let mut total_functions = 0usize;

	for i in 0..max_descriptors {
		if imports.len() >= MAX_IMPORTS {
			break;
		}

		let base = i * 20;
		let original_first_thunk = read_u32(&desc_data, base)?;
		let name_rva = read_u32(&desc_data, base + 12)?;

		// Null-terminated: all fields zero
		if original_first_thunk == 0 && name_rva == 0 {
			break;
		}

		// Read DLL name
		let dll_name = if name_rva != 0 {
			let name_offset = resolve_rva(name_rva, kind, sections).ok_or_else(|| {
				MyceliumError::ParseError(format!(
					"cannot resolve import DLL name RVA 0x{name_rva:08X}"
				))
			})?;
			read_cstring(reader, name_offset, 256)?
		} else {
			String::new()
		};

		// Walk thunk entries to get function names
		let thunk_rva = if original_first_thunk != 0 {
			original_first_thunk
		} else {
			// Fall back to FirstThunk if OriginalFirstThunk is zero
			read_u32(&desc_data, base + 16)?
		};

		let functions = if thunk_rva != 0 {
			parse_import_thunks(
				reader,
				thunk_rva,
				sections,
				kind,
				is_pe32_plus,
				&mut total_functions,
			)?
		} else {
			Vec::new()
		};

		imports.push(PeImport {
			dll_name,
			functions,
		});
	}

	Ok(imports)
}

fn parse_import_thunks(
	reader: &dyn PeReader,
	thunk_rva: u32,
	sections: &[SectionHeader],
	kind: &ReaderKind,
	is_pe32_plus: bool,
	total_functions: &mut usize,
) -> Result<Vec<String>> {
	let thunk_offset = resolve_rva(thunk_rva, kind, sections).ok_or_else(|| {
		MyceliumError::ParseError(format!("cannot resolve import thunk RVA 0x{thunk_rva:08X}"))
	})?;

	let thunk_size: usize = if is_pe32_plus { 8 } else { 4 };
	let ordinal_flag: u64 = if is_pe32_plus { 1u64 << 63 } else { 1u64 << 31 };

	let mut functions = Vec::new();

	// Read thunks in small batches to avoid huge allocations
	let batch_count = 64;
	let mut batch_offset = thunk_offset;

	'outer: loop {
		let batch_size = batch_count * thunk_size;
		let batch_data = match reader.read_at(batch_offset, batch_size) {
			Ok(d) => d,
			Err(_) => break,
		};

		for j in 0..batch_count {
			if *total_functions >= MAX_IMPORT_FUNCTIONS {
				break 'outer;
			}

			let off = j * thunk_size;
			let thunk_value = if is_pe32_plus {
				read_u64(&batch_data, off)?
			} else {
				read_u32(&batch_data, off)? as u64
			};

			if thunk_value == 0 {
				break 'outer;
			}

			if thunk_value & ordinal_flag != 0 {
				// Import by ordinal
				let ordinal = (thunk_value & 0xFFFF) as u16;
				functions.push(format!("ordinal#{ordinal}"));
			} else {
				// Import by name: thunk_value is an RVA to IMAGE_IMPORT_BY_NAME
				// (2-byte hint + null-terminated name)
				let hint_rva = thunk_value as u32;
				if let Some(hint_offset) = resolve_rva(hint_rva, kind, sections) {
					// Skip 2-byte hint, read the name
					match read_cstring(reader, hint_offset + 2, 256) {
						Ok(name) => functions.push(name),
						Err(_) => functions.push(format!("rva#0x{hint_rva:08X}")),
					}
				} else {
					functions.push(format!("rva#0x{hint_rva:08X}"));
				}
			}

			*total_functions += 1;
		}

		batch_offset += batch_size;
	}

	Ok(functions)
}

// ---------------------------------------------------------------------------
// Export parsing
// ---------------------------------------------------------------------------

fn parse_exports(
	reader: &dyn PeReader,
	export_rva: u32,
	_export_size: u32,
	sections: &[SectionHeader],
	kind: &ReaderKind,
) -> Result<Vec<PeExport>> {
	let export_offset = resolve_rva(export_rva, kind, sections).ok_or_else(|| {
		MyceliumError::ParseError("cannot resolve export directory RVA".to_string())
	})?;

	// Export directory structure (40 bytes):
	//   +0  Characteristics (u32)
	//   +4  TimeDateStamp (u32)
	//   +8  MajorVersion (u16)
	//  +10  MinorVersion (u16)
	//  +12  Name (u32 RVA)
	//  +16  Base (u32)
	//  +20  NumberOfFunctions (u32)
	//  +24  NumberOfNames (u32)
	//  +28  AddressOfFunctions (u32 RVA)
	//  +32  AddressOfNames (u32 RVA)
	//  +36  AddressOfNameOrdinals (u32 RVA)
	let dir = reader.read_at(export_offset, 40)?;

	let base_ordinal = read_u32(&dir, 16)?;
	let number_of_functions = read_u32(&dir, 20)? as usize;
	let number_of_names = read_u32(&dir, 24)? as usize;
	let addr_of_functions_rva = read_u32(&dir, 28)?;
	let addr_of_names_rva = read_u32(&dir, 32)?;
	let addr_of_name_ordinals_rva = read_u32(&dir, 36)?;

	if number_of_functions > MAX_EXPORTS || number_of_names > MAX_EXPORTS {
		return Err(MyceliumError::ParseError(format!(
			"too many exports: functions={number_of_functions}, names={number_of_names} (max {MAX_EXPORTS})"
		)));
	}

	// Read the AddressOfFunctions array (u32 each)
	let functions_offset = resolve_rva(addr_of_functions_rva, kind, sections).ok_or_else(|| {
		MyceliumError::ParseError("cannot resolve AddressOfFunctions RVA".to_string())
	})?;
	let functions_data = reader.read_at(functions_offset, number_of_functions * 4)?;

	// Read the AddressOfNames array (u32 RVAs each)
	let names_data = if number_of_names > 0 && addr_of_names_rva != 0 {
		let names_offset = resolve_rva(addr_of_names_rva, kind, sections).ok_or_else(|| {
			MyceliumError::ParseError("cannot resolve AddressOfNames RVA".to_string())
		})?;
		reader.read_at(names_offset, number_of_names * 4)?
	} else {
		Vec::new()
	};

	// Read the AddressOfNameOrdinals array (u16 each)
	let ordinals_data = if number_of_names > 0 && addr_of_name_ordinals_rva != 0 {
		let ordinals_offset =
			resolve_rva(addr_of_name_ordinals_rva, kind, sections).ok_or_else(|| {
				MyceliumError::ParseError("cannot resolve AddressOfNameOrdinals RVA".to_string())
			})?;
		reader.read_at(ordinals_offset, number_of_names * 2)?
	} else {
		Vec::new()
	};

	// Build a mapping from function index -> name
	let mut name_map: Vec<Option<String>> = vec![None; number_of_functions];

	for i in 0..number_of_names {
		let name_rva = read_u32(&names_data, i * 4)?;
		let ordinal_index = read_u16(&ordinals_data, i * 2)? as usize;

		if ordinal_index < number_of_functions {
			let name_offset = resolve_rva(name_rva, kind, sections);
			if let Some(off) = name_offset
				&& let Ok(name) = read_cstring(reader, off, 256)
			{
				name_map[ordinal_index] = Some(name);
			}
		}
	}

	// Build export entries
	let mut exports = Vec::with_capacity(number_of_functions);

	for (i, mapped_name) in name_map.iter().enumerate().take(number_of_functions) {
		let rva = read_u32(&functions_data, i * 4)?;
		if rva == 0 {
			continue; // unused export slot
		}

		let ordinal = (base_ordinal as usize + i) as u16;

		exports.push(PeExport {
			ordinal,
			name: mapped_name.clone(),
			rva,
		});
	}

	Ok(exports)
}

// ---------------------------------------------------------------------------
// Find the base address of the main module in a process
// ---------------------------------------------------------------------------

fn find_process_base_address(handle: HANDLE) -> Result<usize> {
	let mut hmodules = [Default::default(); 1];
	let mut cb_needed: u32 = 0;

	unsafe {
		EnumProcessModules(
			handle,
			hmodules.as_mut_ptr(),
			mem::size_of_val(&hmodules) as u32,
			&mut cb_needed,
		)
	}
	.map_err(|e| MyceliumError::OsError {
		code: e.code().0,
		message: format!("EnumProcessModules failed: {e}"),
	})?;

	if cb_needed == 0 {
		return Err(MyceliumError::ParseError(
			"process has no modules".to_string(),
		));
	}

	// First module is the main executable
	let mut mod_info: MODULEINFO = unsafe { mem::zeroed() };
	unsafe {
		GetModuleInformation(
			handle,
			hmodules[0],
			&mut mod_info,
			mem::size_of::<MODULEINFO>() as u32,
		)
	}
	.map_err(|e| MyceliumError::OsError {
		code: e.code().0,
		message: format!("GetModuleInformation failed: {e}"),
	})?;

	Ok(mod_info.lpBaseOfDll as usize)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Inspect a PE binary, reading either from a file on disk or from a live
/// process's memory.
pub(crate) fn inspect_pe(target: &PeTarget) -> Result<PeInfo> {
	match target {
		PeTarget::Path(path) => {
			let data = std::fs::read(path).map_err(|e| {
				MyceliumError::IoError(std::io::Error::new(
					e.kind(),
					format!("cannot read PE file \"{path}\": {e}"),
				))
			})?;

			if data.len() > MAX_PE_READ {
				return Err(MyceliumError::ParseError(format!(
					"PE file is {} bytes, exceeds maximum of {MAX_PE_READ} bytes",
					data.len()
				)));
			}

			let reader = FilePeReader { data };
			parse_pe(&reader, &ReaderKind::File)
		}
		PeTarget::Pid(pid) => {
			crate::privilege::ensure_debug_privilege()?;

			let handle =
				SafeHandle::open_process(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, *pid)
					.map_err(|e| {
						MyceliumError::PermissionDenied(format!("cannot open process {pid}: {e}"))
					})?;

			let base_address = find_process_base_address(handle.raw())?;

			let reader = ProcessPeReader {
				handle,
				base_address,
			};

			parse_pe(&reader, &ReaderKind::Process)
		}
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
	use super::*;

	// -- read_u16 / read_u32 / read_u64 --

	#[test]
	fn test_read_u16_valid() {
		let data = [0x34, 0x12];
		assert_eq!(read_u16(&data, 0).unwrap(), 0x1234);
	}

	#[test]
	fn test_read_u16_with_offset() {
		let data = [0x00, 0xAB, 0xCD];
		assert_eq!(read_u16(&data, 1).unwrap(), 0xCDAB);
	}

	#[test]
	fn test_read_u16_out_of_bounds() {
		let data = [0xFF];
		assert!(read_u16(&data, 0).is_err());
	}

	#[test]
	fn test_read_u16_offset_out_of_bounds() {
		let data = [0x01, 0x02];
		assert!(read_u16(&data, 1).is_err());
	}

	#[test]
	fn test_read_u32_valid() {
		let data = [0x78, 0x56, 0x34, 0x12];
		assert_eq!(read_u32(&data, 0).unwrap(), 0x12345678);
	}

	#[test]
	fn test_read_u32_with_offset() {
		let data = [0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE];
		assert_eq!(read_u32(&data, 2).unwrap(), 0xDEADBEEF);
	}

	#[test]
	fn test_read_u32_out_of_bounds() {
		let data = [0x01, 0x02, 0x03];
		assert!(read_u32(&data, 0).is_err());
	}

	#[test]
	fn test_read_u64_valid() {
		let data = [0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12];
		assert_eq!(read_u64(&data, 0).unwrap(), 0x1234567890ABCDEF);
	}

	#[test]
	fn test_read_u64_out_of_bounds() {
		let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
		assert!(read_u64(&data, 0).is_err());
	}

	#[test]
	fn test_read_u64_offset_overflow() {
		let data = [0x00; 8];
		assert!(read_u64(&data, usize::MAX).is_err());
	}

	// -- rva_to_file_offset --

	fn make_sections() -> Vec<SectionHeader> {
		vec![
			SectionHeader {
				name: ".text".to_string(),
				virtual_address: 0x1000,
				virtual_size: 0x2000,
				size_of_raw_data: 0x2000,
				pointer_to_raw_data: 0x400,
				characteristics: 0x6000_0020,
			},
			SectionHeader {
				name: ".rdata".to_string(),
				virtual_address: 0x3000,
				virtual_size: 0x1000,
				size_of_raw_data: 0x1000,
				pointer_to_raw_data: 0x2400,
				characteristics: 0x4000_0040,
			},
			SectionHeader {
				name: ".data".to_string(),
				virtual_address: 0x4000,
				virtual_size: 0x500,
				size_of_raw_data: 0x200,
				pointer_to_raw_data: 0x3400,
				characteristics: 0xC000_0040,
			},
		]
	}

	#[test]
	fn test_rva_to_file_offset_text_start() {
		let sections = make_sections();
		// RVA 0x1000 is start of .text -> file offset 0x400
		assert_eq!(rva_to_file_offset(0x1000, &sections), Some(0x400));
	}

	#[test]
	fn test_rva_to_file_offset_text_middle() {
		let sections = make_sections();
		// RVA 0x1500 is inside .text -> 0x1500 - 0x1000 + 0x400 = 0x900
		assert_eq!(rva_to_file_offset(0x1500, &sections), Some(0x900));
	}

	#[test]
	fn test_rva_to_file_offset_rdata() {
		let sections = make_sections();
		// RVA 0x3100 is inside .rdata -> 0x3100 - 0x3000 + 0x2400 = 0x2500
		assert_eq!(rva_to_file_offset(0x3100, &sections), Some(0x2500));
	}

	#[test]
	fn test_rva_to_file_offset_data() {
		let sections = make_sections();
		// RVA 0x4000 is start of .data -> 0x4000 - 0x4000 + 0x3400 = 0x3400
		assert_eq!(rva_to_file_offset(0x4000, &sections), Some(0x3400));
	}

	#[test]
	fn test_rva_to_file_offset_before_all_sections() {
		let sections = make_sections();
		// RVA 0x100 is before any section
		assert_eq!(rva_to_file_offset(0x100, &sections), None);
	}

	#[test]
	fn test_rva_to_file_offset_between_sections() {
		let sections = make_sections();
		// RVA 0x2FFF is between .text (ends at 0x3000) and .rdata (starts at 0x3000)
		// It's at 0x1000 + 0x2000 - 1 = 0x2FFF which is the last byte of .text
		assert_eq!(rva_to_file_offset(0x2FFF, &sections), Some(0x23FF));
	}

	#[test]
	fn test_rva_to_file_offset_past_all_sections() {
		let sections = make_sections();
		// RVA 0x5000 is after all sections
		assert_eq!(rva_to_file_offset(0x5000, &sections), None);
	}

	#[test]
	fn test_rva_to_file_offset_empty_sections() {
		let sections: Vec<SectionHeader> = Vec::new();
		assert_eq!(rva_to_file_offset(0x1000, &sections), None);
	}

	// -- parse_pe with minimal valid PE --

	/// Build a minimal valid PE32 (x86) binary in memory.
	///
	/// Layout:
	///   0x00  DOS header (64 bytes, e_lfanew = 0x40)
	///   0x40  PE signature (4 bytes)
	///   0x44  COFF header (20 bytes)
	///   0x58  Optional header (PE32, 96 bytes standard + 128 bytes data dirs = 224 bytes)
	///   0x138 Section headers (1 section = 40 bytes)
	///   0x160 end of headers
	///   0x200 .text section data (512 bytes of 0xCC)
	fn build_minimal_pe32() -> Vec<u8> {
		let mut pe = vec![0u8; 0x400]; // 1024 bytes total

		// DOS header
		pe[0] = b'M';
		pe[1] = b'Z';
		// e_lfanew at offset 0x3C = 0x40
		pe[0x3C] = 0x40;

		// PE signature at 0x40
		pe[0x40] = b'P';
		pe[0x41] = b'E';
		pe[0x42] = 0;
		pe[0x43] = 0;

		// COFF header at 0x44 (20 bytes)
		let coff = 0x44;
		// Machine = 0x14C (x86)
		pe[coff] = 0x4C;
		pe[coff + 1] = 0x01;
		// NumberOfSections = 1
		pe[coff + 2] = 0x01;
		pe[coff + 3] = 0x00;
		// TimeDateStamp = 0x5F3E2D1C
		pe[coff + 4] = 0x1C;
		pe[coff + 5] = 0x2D;
		pe[coff + 6] = 0x3E;
		pe[coff + 7] = 0x5F;
		// PointerToSymbolTable = 0
		// NumberOfSymbols = 0
		// SizeOfOptionalHeader = 224 (0xE0) for PE32
		pe[coff + 16] = 0xE0;
		pe[coff + 17] = 0x00;
		// Characteristics = 0x0102 (EXECUTABLE | 32BIT_MACHINE)
		pe[coff + 18] = 0x02;
		pe[coff + 19] = 0x01;

		// Optional header at 0x58 (224 bytes for PE32)
		let opt = 0x58;
		// Magic = 0x10B (PE32)
		pe[opt] = 0x0B;
		pe[opt + 1] = 0x01;
		// MajorLinkerVersion = 14
		pe[opt + 2] = 0x0E;
		// MinorLinkerVersion = 0
		pe[opt + 3] = 0x00;
		// SizeOfCode = 0x200
		pe[opt + 4] = 0x00;
		pe[opt + 5] = 0x02;
		// EntryPoint at opt+16 = 0x1000
		pe[opt + 16] = 0x00;
		pe[opt + 17] = 0x10;
		pe[opt + 18] = 0x00;
		pe[opt + 19] = 0x00;
		// ImageBase at opt+28 = 0x00400000
		pe[opt + 28] = 0x00;
		pe[opt + 29] = 0x00;
		pe[opt + 30] = 0x40;
		pe[opt + 31] = 0x00;
		// SectionAlignment at opt+32 = 0x1000
		pe[opt + 32] = 0x00;
		pe[opt + 33] = 0x10;
		// FileAlignment at opt+36 = 0x200
		pe[opt + 36] = 0x00;
		pe[opt + 37] = 0x02;
		// SizeOfImage at opt+56 = 0x3000
		pe[opt + 56] = 0x00;
		pe[opt + 57] = 0x30;
		pe[opt + 58] = 0x00;
		pe[opt + 59] = 0x00;
		// SizeOfHeaders at opt+60 = 0x200
		pe[opt + 60] = 0x00;
		pe[opt + 61] = 0x02;
		// Subsystem at opt+68 = 3 (Console)
		pe[opt + 68] = 0x03;
		pe[opt + 69] = 0x00;
		// NumberOfRvaAndSizes at opt+92 = 16
		pe[opt + 92] = 0x10;
		pe[opt + 93] = 0x00;
		pe[opt + 94] = 0x00;
		pe[opt + 95] = 0x00;
		// Data directories (16 * 8 = 128 bytes) all zero (no imports/exports)

		// Section headers start at opt + 224 = 0x58 + 0xE0 = 0x138
		let sec = 0x138;
		// Name = ".text\0\0\0"
		pe[sec] = b'.';
		pe[sec + 1] = b't';
		pe[sec + 2] = b'e';
		pe[sec + 3] = b'x';
		pe[sec + 4] = b't';
		// VirtualSize at sec+8 = 0x200
		pe[sec + 8] = 0x00;
		pe[sec + 9] = 0x02;
		// VirtualAddress at sec+12 = 0x1000
		pe[sec + 12] = 0x00;
		pe[sec + 13] = 0x10;
		// SizeOfRawData at sec+16 = 0x200
		pe[sec + 16] = 0x00;
		pe[sec + 17] = 0x02;
		// PointerToRawData at sec+20 = 0x200
		pe[sec + 20] = 0x00;
		pe[sec + 21] = 0x02;
		// Characteristics at sec+36 = 0x60000020 (CODE | EXECUTE | READ)
		pe[sec + 36] = 0x20;
		pe[sec + 37] = 0x00;
		pe[sec + 38] = 0x00;
		pe[sec + 39] = 0x60;

		// .text section data at 0x200 (512 bytes of 0xCC = INT3)
		for byte in &mut pe[0x200..0x400] {
			*byte = 0xCC;
		}

		pe
	}

	#[test]
	fn test_parse_pe_minimal_pe32() {
		let data = build_minimal_pe32();
		let reader = FilePeReader { data };
		let info = parse_pe(&reader, &ReaderKind::File).unwrap();

		assert_eq!(info.machine, "x86");
		assert!(info.characteristics.contains(&"EXECUTABLE".to_string()));
		assert_eq!(info.entry_point, 0x1000);
		assert_eq!(info.image_base, 0x0040_0000);
		assert_eq!(info.image_size, 0x3000);
		assert_eq!(info.timestamp, 0x5F3E2D1C);
		assert_eq!(info.subsystem, "Console");
		assert_eq!(info.sections.len(), 1);
		assert_eq!(info.sections[0].name, ".text");
		assert_eq!(info.sections[0].virtual_address, 0x1000);
		assert_eq!(info.sections[0].virtual_size, 0x200);
		assert_eq!(info.sections[0].raw_size, 0x200);
		assert!(
			info.sections[0]
				.characteristics
				.contains(&"CODE".to_string())
		);
		assert!(
			info.sections[0]
				.characteristics
				.contains(&"EXECUTE".to_string())
		);
		assert!(
			info.sections[0]
				.characteristics
				.contains(&"READ".to_string())
		);
		assert!(info.imports.is_empty());
		assert!(info.exports.is_empty());
	}

	#[test]
	fn test_parse_pe_invalid_dos_signature() {
		let mut data = build_minimal_pe32();
		data[0] = b'X'; // corrupt MZ
		let reader = FilePeReader { data };
		let err = parse_pe(&reader, &ReaderKind::File).unwrap_err();
		assert!(err.to_string().contains("MZ"));
	}

	#[test]
	fn test_parse_pe_invalid_pe_signature() {
		let mut data = build_minimal_pe32();
		data[0x40] = b'X'; // corrupt PE\0\0
		let reader = FilePeReader { data };
		let err = parse_pe(&reader, &ReaderKind::File).unwrap_err();
		assert!(err.to_string().contains("PE"));
	}

	#[test]
	fn test_parse_pe_too_short() {
		let data = vec![b'M', b'Z'];
		let reader = FilePeReader { data };
		assert!(parse_pe(&reader, &ReaderKind::File).is_err());
	}

	// -- decode helpers --

	#[test]
	fn test_machine_to_string() {
		assert_eq!(machine_to_string(0x014C), "x86");
		assert_eq!(machine_to_string(0x8664), "x64");
		assert_eq!(machine_to_string(0xAA64), "ARM64");
		assert!(machine_to_string(0x1234).starts_with("unknown"));
	}

	#[test]
	fn test_subsystem_to_string() {
		assert_eq!(subsystem_to_string(1), "Native");
		assert_eq!(subsystem_to_string(2), "GUI");
		assert_eq!(subsystem_to_string(3), "Console");
		assert!(subsystem_to_string(99).starts_with("unknown"));
	}

	#[test]
	fn test_decode_coff_characteristics() {
		let flags = decode_coff_characteristics(0x2022);
		assert!(flags.contains(&"EXECUTABLE".to_string()));
		assert!(flags.contains(&"LARGE_ADDRESS_AWARE".to_string()));
		assert!(flags.contains(&"DLL".to_string()));
	}

	#[test]
	fn test_decode_coff_characteristics_executable_only() {
		let flags = decode_coff_characteristics(0x0002);
		assert_eq!(flags, vec!["EXECUTABLE".to_string()]);
	}

	#[test]
	fn test_decode_section_characteristics() {
		let flags = decode_section_characteristics(0xE000_0020);
		assert!(flags.contains(&"CODE".to_string()));
		assert!(flags.contains(&"EXECUTE".to_string()));
		assert!(flags.contains(&"READ".to_string()));
		assert!(flags.contains(&"WRITE".to_string()));
	}

	#[test]
	fn test_decode_section_characteristics_read_only() {
		let flags = decode_section_characteristics(0x4000_0000);
		assert_eq!(flags, vec!["READ".to_string()]);
	}
}
