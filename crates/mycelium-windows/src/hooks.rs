//! API hook detection — inline, IAT, and EAT hook scanning.

use std::collections::HashSet;
use std::mem;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::ProcessStatus::{
	EnumProcessModules, GetModuleFileNameExW, GetModuleInformation, MODULEINFO,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

use mycelium_core::error::{MyceliumError, Result};
use mycelium_core::types::{HookInfo, HookType};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_MODULES_TO_SCAN: usize = 10;
const MAX_EXPORTS_PER_MODULE: usize = 10_000;
const INLINE_HOOK_SCAN_BYTES: usize = 16;

/// Maximum number of modules to enumerate per process.
const MAX_MODULES: usize = 4_096;

/// Maximum on-disk DLL size we are willing to read (64 MiB).
const MAX_DLL_FILE_SIZE: u64 = 64 * 1024 * 1024;

/// Critical DLLs to scan for inline hooks.
const CRITICAL_DLLS: &[&str] = &[
	"ntdll.dll",
	"kernel32.dll",
	"kernelbase.dll",
	"advapi32.dll",
	"user32.dll",
];

// ---------------------------------------------------------------------------
// SafeHandle RAII wrapper
// ---------------------------------------------------------------------------

/// RAII guard for a Windows HANDLE. Automatically calls `CloseHandle` on drop.
struct SafeHandle(HANDLE);

impl Drop for SafeHandle {
	fn drop(&mut self) {
		unsafe {
			let _ = CloseHandle(self.0);
		}
	}
}

impl SafeHandle {
	/// Open a process with the specified access rights.
	fn open_process(access: u32, pid: u32) -> Result<Self> {
		let handle = unsafe {
			OpenProcess(
				windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS(access),
				false,
				pid,
			)
		}
		.map_err(|e| MyceliumError::PermissionDenied(format!("cannot open process {pid}: {e}")))?;
		Ok(Self(handle))
	}

	/// Get the raw HANDLE value.
	fn raw(&self) -> HANDLE {
		self.0
	}
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// Information about a loaded module in the target process.
struct ModuleInfo {
	name: String,
	base_address: u64,
	size: u32,
	path: String,
}

/// A parsed PE export entry.
struct ExportEntry {
	name: Option<String>,
	#[allow(dead_code)]
	ordinal: u16,
	rva: u32,
}

/// Collection of PE exports.
struct PeExports {
	functions: Vec<ExportEntry>,
}

/// A PE section header entry.
#[derive(Debug, PartialEq)]
struct SectionEntry {
	name: String,
	virtual_address: u32,
	virtual_size: u32,
	pointer_to_raw_data: u32,
	size_of_raw_data: u32,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Detect API hooks (inline, IAT, EAT) in the target process.
///
/// Opens the process, enumerates its modules, and runs three detection methods.
/// Individual module failures are logged and skipped rather than propagated.
pub(crate) fn detect_hooks(pid: u32) -> Result<Vec<HookInfo>> {
	let _ = crate::privilege::ensure_debug_privilege();

	let handle = SafeHandle::open_process(PROCESS_QUERY_INFORMATION.0 | PROCESS_VM_READ.0, pid)?;

	let modules = enumerate_modules(handle.raw())?;
	let mut hooks = Vec::new();

	detect_inline_hooks(handle.raw(), &modules, &mut hooks)?;
	detect_iat_hooks(handle.raw(), &modules, &mut hooks)?;
	detect_eat_hooks(handle.raw(), &modules, &mut hooks)?;

	Ok(hooks)
}

// ---------------------------------------------------------------------------
// Module enumeration
// ---------------------------------------------------------------------------

/// Enumerate all modules loaded in the target process.
fn enumerate_modules(handle: HANDLE) -> Result<Vec<ModuleInfo>> {
	let mut hmodules = vec![Default::default(); MAX_MODULES];
	let mut cb_needed: u32 = 0;

	unsafe {
		EnumProcessModules(
			handle,
			hmodules.as_mut_ptr(),
			(hmodules.len() * mem::size_of::<windows::Win32::Foundation::HMODULE>()) as u32,
			&mut cb_needed,
		)
	}
	.map_err(|e| MyceliumError::OsError {
		code: e.code().0,
		message: format!("EnumProcessModules failed: {e}"),
	})?;

	let count = cb_needed as usize / mem::size_of::<windows::Win32::Foundation::HMODULE>();
	hmodules.truncate(count);

	let mut modules = Vec::with_capacity(count);

	for hmod in &hmodules {
		let mut name_buf = [0u16; 260];
		let name_len =
			unsafe { GetModuleFileNameExW(Some(handle), Some(*hmod), &mut name_buf) } as usize;

		let path = if name_len > 0 {
			String::from_utf16_lossy(&name_buf[..name_len])
		} else {
			String::new()
		};

		let name = path
			.rsplit_once('\\')
			.map(|(_, n)| n.to_string())
			.unwrap_or_else(|| path.clone());

		let mut mod_info: MODULEINFO = unsafe { mem::zeroed() };
		let got_info = unsafe {
			GetModuleInformation(
				handle,
				*hmod,
				&mut mod_info,
				mem::size_of::<MODULEINFO>() as u32,
			)
		};

		let (base_address, size) = if got_info.is_ok() {
			(mod_info.lpBaseOfDll as u64, mod_info.SizeOfImage)
		} else {
			(0, 0)
		};

		modules.push(ModuleInfo {
			name,
			base_address,
			size,
			path,
		});
	}

	Ok(modules)
}

// ---------------------------------------------------------------------------
// Process memory helpers
// ---------------------------------------------------------------------------

/// Safely read memory from a remote process, returning `None` on failure.
fn read_process_memory_safe(handle: HANDLE, address: u64, size: usize) -> Option<Vec<u8>> {
	let mut buffer = vec![0u8; size];
	let mut bytes_read = 0;
	unsafe {
		ReadProcessMemory(
			handle,
			address as *const _,
			buffer.as_mut_ptr() as *mut _,
			size,
			Some(&mut bytes_read),
		)
		.ok()?;
	}
	buffer.truncate(bytes_read);
	Some(buffer)
}

/// Resolve an address to the module it falls within, if any.
fn resolve_address_to_module(addr: u64, modules: &[ModuleInfo]) -> Option<String> {
	for m in modules {
		if addr >= m.base_address && addr < m.base_address + m.size as u64 {
			return Some(m.name.clone());
		}
	}
	None
}

// ---------------------------------------------------------------------------
// PE parsing helpers
// ---------------------------------------------------------------------------

/// Read a u16 from a byte slice at the given offset.
fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
	if offset + 2 > data.len() {
		return None;
	}
	Some(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

/// Read a u32 from a byte slice at the given offset.
fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
	if offset + 4 > data.len() {
		return None;
	}
	Some(u32::from_le_bytes([
		data[offset],
		data[offset + 1],
		data[offset + 2],
		data[offset + 3],
	]))
}

/// Convert an RVA to a file offset using the section table.
fn rva_to_file_offset(rva: u32, sections: &[SectionEntry]) -> Option<usize> {
	for s in sections {
		if rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size {
			let offset_within_section = rva - s.virtual_address;
			if offset_within_section < s.size_of_raw_data {
				return Some((s.pointer_to_raw_data + offset_within_section) as usize);
			}
		}
	}
	None
}

/// Parse section headers from a PE file.
fn parse_pe_sections(data: &[u8]) -> Option<Vec<SectionEntry>> {
	// DOS header: e_lfanew at offset 0x3C
	if data.len() < 0x40 {
		return None;
	}
	let e_lfanew = read_u32(data, 0x3C)? as usize;

	// PE signature: "PE\0\0" at e_lfanew
	if e_lfanew + 4 > data.len() {
		return None;
	}
	if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
		return None;
	}

	let coff_header = e_lfanew + 4;
	if coff_header + 20 > data.len() {
		return None;
	}

	let number_of_sections = read_u16(data, coff_header + 2)? as usize;
	let size_of_optional_header = read_u16(data, coff_header + 16)? as usize;

	let sections_offset = coff_header + 20 + size_of_optional_header;
	let section_size = 40; // IMAGE_SECTION_HEADER is 40 bytes

	let mut sections = Vec::with_capacity(number_of_sections);
	for i in 0..number_of_sections {
		let base = sections_offset + i * section_size;
		if base + section_size > data.len() {
			break;
		}

		// Name: 8 bytes at offset 0
		let name_bytes = &data[base..base + 8];
		let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
		let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();

		let virtual_size = read_u32(data, base + 8)?;
		let virtual_address = read_u32(data, base + 12)?;
		let size_of_raw_data = read_u32(data, base + 16)?;
		let pointer_to_raw_data = read_u32(data, base + 20)?;

		sections.push(SectionEntry {
			name,
			virtual_address,
			virtual_size,
			pointer_to_raw_data,
			size_of_raw_data,
		});
	}

	Some(sections)
}

/// Parse the export table from a PE file on disk.
fn parse_pe_exports(data: &[u8]) -> Option<PeExports> {
	let sections = parse_pe_sections(data)?;

	// Locate the optional header
	let e_lfanew = read_u32(data, 0x3C)? as usize;
	let coff_header = e_lfanew + 4;
	let optional_header = coff_header + 20;

	if optional_header + 2 > data.len() {
		return None;
	}

	// Determine PE32 vs PE32+
	let magic = read_u16(data, optional_header)?;
	let export_dir_rva_offset = match magic {
		0x10B => optional_header + 96,  // PE32: data directories at offset 96
		0x20B => optional_header + 112, // PE32+: data directories at offset 112
		_ => return None,
	};

	if export_dir_rva_offset + 8 > data.len() {
		return None;
	}

	let export_rva = read_u32(data, export_dir_rva_offset)?;
	let export_size = read_u32(data, export_dir_rva_offset + 4)?;

	if export_rva == 0 || export_size == 0 {
		return Some(PeExports {
			functions: Vec::new(),
		});
	}

	let export_offset = rva_to_file_offset(export_rva, &sections)?;
	if export_offset + 40 > data.len() {
		return None;
	}

	// IMAGE_EXPORT_DIRECTORY fields
	let number_of_functions = read_u32(data, export_offset + 20)? as usize;
	let number_of_names = read_u32(data, export_offset + 24)? as usize;
	let address_of_functions_rva = read_u32(data, export_offset + 28)?;
	let address_of_names_rva = read_u32(data, export_offset + 32)?;
	let address_of_name_ordinals_rva = read_u32(data, export_offset + 36)?;
	let ordinal_base = read_u32(data, export_offset + 16)?;

	let functions_offset = rva_to_file_offset(address_of_functions_rva, &sections)?;
	let names_offset = rva_to_file_offset(address_of_names_rva, &sections)?;
	let ordinals_offset = rva_to_file_offset(address_of_name_ordinals_rva, &sections)?;

	// Cap to avoid excessive allocations on malformed PEs
	let num_functions = number_of_functions.min(MAX_EXPORTS_PER_MODULE);
	let num_names = number_of_names.min(MAX_EXPORTS_PER_MODULE);

	// Build ordinal → name map
	let mut ordinal_to_name: Vec<Option<String>> = vec![None; num_functions];
	for i in 0..num_names {
		let name_rva_off = names_offset + i * 4;
		let ordinal_off = ordinals_offset + i * 2;

		let name_rva = match read_u32(data, name_rva_off) {
			Some(v) => v,
			None => continue,
		};
		let ordinal_index = match read_u16(data, ordinal_off) {
			Some(v) => v as usize,
			None => continue,
		};

		if ordinal_index >= num_functions {
			continue;
		}

		let name_file_off = match rva_to_file_offset(name_rva, &sections) {
			Some(v) => v,
			None => continue,
		};

		// Read null-terminated ASCII name
		let name_end = data[name_file_off..]
			.iter()
			.position(|&b| b == 0)
			.unwrap_or(256.min(data.len() - name_file_off));
		let name =
			String::from_utf8_lossy(&data[name_file_off..name_file_off + name_end]).to_string();

		ordinal_to_name[ordinal_index] = Some(name);
	}

	// Build export entries
	let mut functions = Vec::with_capacity(num_functions);
	for (i, name) in ordinal_to_name.iter().enumerate().take(num_functions) {
		let func_rva_off = functions_offset + i * 4;
		let func_rva = match read_u32(data, func_rva_off) {
			Some(v) => v,
			None => continue,
		};

		// Skip forwarder RVAs (they point within the export directory)
		if func_rva >= export_rva && func_rva < export_rva + export_size {
			continue;
		}

		if func_rva == 0 {
			continue;
		}

		functions.push(ExportEntry {
			name: name.clone(),
			ordinal: (i as u32 + ordinal_base) as u16,
			rva: func_rva,
		});
	}

	Some(PeExports { functions })
}

/// Parse the .reloc section to build a set of relocated RVAs.
fn parse_relocations(pe_data: &[u8], sections: &[SectionEntry]) -> HashSet<u32> {
	let mut relocated = HashSet::new();

	// Find the .reloc section
	let reloc_section = match sections.iter().find(|s| s.name == ".reloc") {
		Some(s) => s,
		None => return relocated,
	};

	let reloc_start = reloc_section.pointer_to_raw_data as usize;
	let reloc_end = reloc_start + reloc_section.size_of_raw_data as usize;

	if reloc_end > pe_data.len() {
		return relocated;
	}

	let mut offset = reloc_start;
	while offset + 8 <= reloc_end {
		let page_rva = match read_u32(pe_data, offset) {
			Some(v) => v,
			None => break,
		};
		let block_size = match read_u32(pe_data, offset + 4) {
			Some(v) => v as usize,
			None => break,
		};

		// Sanity check block size
		if block_size < 8 || offset + block_size > reloc_end {
			break;
		}

		let num_entries = (block_size - 8) / 2;
		for i in 0..num_entries {
			let entry_offset = offset + 8 + i * 2;
			let entry = match read_u16(pe_data, entry_offset) {
				Some(v) => v,
				None => break,
			};

			let entry_type = entry >> 12;
			let entry_page_offset = (entry & 0x0FFF) as u32;

			match entry_type {
				3 => {
					// IMAGE_REL_BASED_HIGHLOW (32-bit relocation, 4 bytes)
					let rva = page_rva + entry_page_offset;
					for b in 0..4u32 {
						relocated.insert(rva + b);
					}
				}
				10 => {
					// IMAGE_REL_BASED_DIR64 (64-bit relocation, 8 bytes)
					let rva = page_rva + entry_page_offset;
					for b in 0..8u32 {
						relocated.insert(rva + b);
					}
				}
				0 => {
					// IMAGE_REL_BASED_ABSOLUTE — padding, skip
				}
				_ => {
					// Unknown relocation type, skip
				}
			}
		}

		offset += block_size;
	}

	relocated
}

// ---------------------------------------------------------------------------
// Inline hook detection
// ---------------------------------------------------------------------------

/// Check if bytes differ for a non-relocation reason.
fn has_non_relocation_diff(
	mem_bytes: &[u8],
	disk_bytes: &[u8],
	rva: u32,
	relocated: &HashSet<u32>,
) -> bool {
	for i in 0..mem_bytes.len().min(disk_bytes.len()) {
		if mem_bytes[i] != disk_bytes[i] && !relocated.contains(&(rva + i as u32)) {
			return true;
		}
	}
	false
}

/// Detect common inline hook patterns and return the hook destination.
///
/// Patterns detected:
/// - `0xE9 <rel32>`           — JMP rel32
/// - `0xFF 0x25 <disp32>`     — JMP [rip+disp32]
/// - `0x48 0xB8 <imm64> 0xFF 0xE0` — mov rax, imm64; jmp rax
/// - `0x68 <imm32> 0xC3`      — push imm32; ret
fn detect_inline_hook_pattern(bytes: &[u8], address: u64) -> Option<u64> {
	if bytes.len() < 5 {
		return None;
	}

	// JMP rel32
	if bytes[0] == 0xE9 {
		let rel = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
		return Some((address as i64 + 5 + rel as i64) as u64);
	}

	// JMP [rip+disp32]
	if bytes.len() >= 6 && bytes[0] == 0xFF && bytes[1] == 0x25 {
		let disp = i32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
		return Some((address as i64 + 6 + disp as i64) as u64);
	}

	// mov rax, imm64; jmp rax
	if bytes.len() >= 12
		&& bytes[0] == 0x48
		&& bytes[1] == 0xB8
		&& bytes[10] == 0xFF
		&& bytes[11] == 0xE0
	{
		return Some(u64::from_le_bytes([
			bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
		]));
	}

	// push imm32; ret
	if bytes.len() >= 6 && bytes[0] == 0x68 && bytes[5] == 0xC3 {
		return Some(u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as u64);
	}

	None
}

/// Scan critical DLLs for inline hooks by comparing on-disk and in-memory exports.
fn detect_inline_hooks(
	handle: HANDLE,
	modules: &[ModuleInfo],
	hooks: &mut Vec<HookInfo>,
) -> Result<()> {
	for dll_name in CRITICAL_DLLS {
		let module = match modules
			.iter()
			.find(|m| m.name.eq_ignore_ascii_case(dll_name))
		{
			Some(m) => m,
			None => continue,
		};

		if module.path.is_empty() || module.base_address == 0 {
			continue;
		}

		if let Err(e) = scan_module_inline_hooks(handle, module, modules, hooks) {
			tracing::debug!(
				module = %module.name,
				error = %e,
				"failed to scan module for inline hooks, skipping"
			);
		}
	}

	Ok(())
}

/// Scan a single module for inline hooks.
fn scan_module_inline_hooks(
	handle: HANDLE,
	module: &ModuleInfo,
	all_modules: &[ModuleInfo],
	hooks: &mut Vec<HookInfo>,
) -> Result<()> {
	// Read the on-disk DLL
	let metadata = std::fs::metadata(&module.path).map_err(MyceliumError::IoError)?;
	if metadata.len() > MAX_DLL_FILE_SIZE {
		return Err(MyceliumError::ParseError(format!(
			"DLL file too large: {} bytes",
			metadata.len()
		)));
	}

	let disk_data = std::fs::read(&module.path).map_err(MyceliumError::IoError)?;

	// Parse PE exports
	let exports = match parse_pe_exports(&disk_data) {
		Some(e) => e,
		None => {
			return Err(MyceliumError::ParseError(format!(
				"failed to parse PE exports for {}",
				module.name
			)));
		}
	};

	// Parse sections
	let sections = match parse_pe_sections(&disk_data) {
		Some(s) => s,
		None => {
			return Err(MyceliumError::ParseError(format!(
				"failed to parse PE sections for {}",
				module.name
			)));
		}
	};

	// Parse relocations
	let relocated = parse_relocations(&disk_data, &sections);

	// Scan each exported function
	for export in &exports.functions {
		let func_name = match &export.name {
			Some(n) => n.clone(),
			None => continue, // Skip unnamed exports
		};

		let rva = export.rva;
		let mem_address = module.base_address + rva as u64;

		// Read bytes from process memory
		let mem_bytes = match read_process_memory_safe(handle, mem_address, INLINE_HOOK_SCAN_BYTES)
		{
			Some(b) if b.len() >= 5 => b,
			_ => continue,
		};

		// Read bytes from on-disk file
		let file_offset = match rva_to_file_offset(rva, &sections) {
			Some(o) => o,
			None => continue,
		};

		if file_offset + INLINE_HOOK_SCAN_BYTES > disk_data.len() {
			continue;
		}

		let disk_bytes = &disk_data[file_offset..file_offset + INLINE_HOOK_SCAN_BYTES];
		let compare_len = mem_bytes.len().min(INLINE_HOOK_SCAN_BYTES);
		let disk_compare = &disk_bytes[..compare_len];
		let mem_compare = &mem_bytes[..compare_len];

		// Check for differences that are not explained by relocations
		if !has_non_relocation_diff(mem_compare, disk_compare, rva, &relocated) {
			continue;
		}

		// Try to match a known hook pattern
		let destination = detect_inline_hook_pattern(&mem_bytes, mem_address);

		// Only report if we found a hook pattern
		if destination.is_none() {
			continue;
		}

		let destination_module =
			destination.and_then(|addr| resolve_address_to_module(addr, all_modules));

		hooks.push(HookInfo {
			hook_type: HookType::InlineHook,
			module: module.name.clone(),
			function: func_name,
			address: mem_address,
			expected_bytes: disk_compare.to_vec(),
			actual_bytes: mem_compare.to_vec(),
			destination,
			destination_module,
		});
	}

	Ok(())
}

// ---------------------------------------------------------------------------
// IAT hook detection
// ---------------------------------------------------------------------------

/// Detect IAT (Import Address Table) hooks in the main module.
///
/// Reads the PE import directory from process memory, checks each IAT slot,
/// and verifies that the resolved address falls within the expected DLL.
fn detect_iat_hooks(
	handle: HANDLE,
	modules: &[ModuleInfo],
	hooks: &mut Vec<HookInfo>,
) -> Result<()> {
	// The main module is the first one
	let main_module = match modules.first() {
		Some(m) => m,
		None => return Ok(()),
	};

	if main_module.base_address == 0 {
		return Ok(());
	}

	if let Err(e) = scan_iat_hooks(handle, main_module, modules, hooks) {
		tracing::debug!(
			module = %main_module.name,
			error = %e,
			"failed to scan IAT hooks, skipping"
		);
	}

	Ok(())
}

/// Scan the IAT of a module for hooks.
fn scan_iat_hooks(
	handle: HANDLE,
	module: &ModuleInfo,
	all_modules: &[ModuleInfo],
	hooks: &mut Vec<HookInfo>,
) -> Result<()> {
	let base = module.base_address;

	// Read the DOS header to get e_lfanew
	let dos_header =
		read_process_memory_safe(handle, base, 0x40).ok_or_else(|| MyceliumError::OsError {
			code: -1,
			message: "failed to read DOS header".to_string(),
		})?;

	let e_lfanew = match read_u32(&dos_header, 0x3C) {
		Some(v) => v as u64,
		None => return Ok(()),
	};

	// Read the PE header (enough for the optional header and data directories)
	let pe_header_addr = base + e_lfanew;
	let pe_header = read_process_memory_safe(handle, pe_header_addr, 512).ok_or_else(|| {
		MyceliumError::OsError {
			code: -1,
			message: "failed to read PE header".to_string(),
		}
	})?;

	// Verify PE signature
	if pe_header.len() < 4 || &pe_header[0..4] != b"PE\0\0" {
		return Ok(());
	}

	// Optional header starts at offset 24 from PE signature
	let optional_header_offset = 24;
	if optional_header_offset + 2 > pe_header.len() {
		return Ok(());
	}

	let magic = read_u16(&pe_header, optional_header_offset)
		.ok_or_else(|| MyceliumError::ParseError("invalid optional header magic".to_string()))?;

	// Import directory RVA is the 2nd data directory entry
	let import_dir_offset = match magic {
		0x10B => optional_header_offset + 96 + 8, // PE32: data dirs at +96, import is 2nd (8 bytes each)
		0x20B => optional_header_offset + 112 + 8, // PE32+: data dirs at +112
		_ => return Ok(()),
	};

	if import_dir_offset + 8 > pe_header.len() {
		return Ok(());
	}

	let import_rva = match read_u32(&pe_header, import_dir_offset) {
		Some(v) => v,
		None => return Ok(()),
	};

	if import_rva == 0 {
		return Ok(());
	}

	// Read import descriptors from process memory
	// Each IMAGE_IMPORT_DESCRIPTOR is 20 bytes, terminated by an all-zero entry
	let import_addr = base + import_rva as u64;
	let max_import_descriptors = MAX_MODULES_TO_SCAN;
	let import_data =
		match read_process_memory_safe(handle, import_addr, max_import_descriptors * 20) {
			Some(d) => d,
			None => return Ok(()),
		};

	for i in 0..max_import_descriptors {
		let desc_offset = i * 20;
		if desc_offset + 20 > import_data.len() {
			break;
		}

		let original_first_thunk_rva = match read_u32(&import_data, desc_offset) {
			Some(v) => v,
			None => break,
		};
		let name_rva = match read_u32(&import_data, desc_offset + 12) {
			Some(v) => v,
			None => break,
		};
		let first_thunk_rva = match read_u32(&import_data, desc_offset + 16) {
			Some(v) => v,
			None => break,
		};

		// All-zero entry marks the end
		if name_rva == 0 && first_thunk_rva == 0 {
			break;
		}

		if name_rva == 0 || first_thunk_rva == 0 {
			continue;
		}

		// Read the DLL name
		let dll_name_addr = base + name_rva as u64;
		let dll_name_bytes = match read_process_memory_safe(handle, dll_name_addr, 256) {
			Some(b) => b,
			None => continue,
		};
		let dll_name_end = dll_name_bytes
			.iter()
			.position(|&b| b == 0)
			.unwrap_or(dll_name_bytes.len());
		let dll_name = String::from_utf8_lossy(&dll_name_bytes[..dll_name_end]).to_string();

		if dll_name.is_empty() {
			continue;
		}

		// Find the expected module for this import
		let expected_module = all_modules
			.iter()
			.find(|m| m.name.eq_ignore_ascii_case(&dll_name));

		let expected_module = match expected_module {
			Some(m) => m,
			None => continue, // Module not loaded, skip
		};

		// Use OriginalFirstThunk for names (if available) and FirstThunk for addresses
		let hint_name_rva = if original_first_thunk_rva != 0 {
			original_first_thunk_rva
		} else {
			first_thunk_rva
		};

		// Read thunk arrays (each entry is 8 bytes on x64)
		let thunk_entry_size = 8usize; // 64-bit
		let max_thunks = 4096;
		let iat_addr = base + first_thunk_rva as u64;
		let ilt_addr = base + hint_name_rva as u64;

		let iat_data =
			match read_process_memory_safe(handle, iat_addr, max_thunks * thunk_entry_size) {
				Some(d) => d,
				None => continue,
			};

		let ilt_data = if hint_name_rva != first_thunk_rva {
			read_process_memory_safe(handle, ilt_addr, max_thunks * thunk_entry_size)
		} else {
			None
		};

		for j in 0..max_thunks {
			let iat_off = j * thunk_entry_size;
			if iat_off + thunk_entry_size > iat_data.len() {
				break;
			}

			// Read the resolved address from the IAT
			let resolved_addr = u64::from_le_bytes([
				iat_data[iat_off],
				iat_data[iat_off + 1],
				iat_data[iat_off + 2],
				iat_data[iat_off + 3],
				iat_data[iat_off + 4],
				iat_data[iat_off + 5],
				iat_data[iat_off + 6],
				iat_data[iat_off + 7],
			]);

			if resolved_addr == 0 {
				break;
			}

			// Try to get function name from the ILT (hint/name table)
			let func_name = if let Some(ref ilt) = ilt_data {
				let ilt_off = j * thunk_entry_size;
				if ilt_off + thunk_entry_size <= ilt.len() {
					let ilt_entry = u64::from_le_bytes([
						ilt[ilt_off],
						ilt[ilt_off + 1],
						ilt[ilt_off + 2],
						ilt[ilt_off + 3],
						ilt[ilt_off + 4],
						ilt[ilt_off + 5],
						ilt[ilt_off + 6],
						ilt[ilt_off + 7],
					]);

					// Check if import is by ordinal (bit 63 set)
					if ilt_entry & (1u64 << 63) != 0 {
						let ordinal = (ilt_entry & 0xFFFF) as u16;
						Some(format!("#{ordinal}"))
					} else if ilt_entry != 0 {
						// Import by name: RVA to IMAGE_IMPORT_BY_NAME (hint: u16, name: char[])
						let name_addr = base + (ilt_entry & 0x7FFFFFFF) + 2; // skip hint
						read_process_memory_safe(handle, name_addr, 256).and_then(|name_bytes| {
							let end = name_bytes
								.iter()
								.position(|&b| b == 0)
								.unwrap_or(name_bytes.len());
							if end > 0 {
								Some(String::from_utf8_lossy(&name_bytes[..end]).to_string())
							} else {
								None
							}
						})
					} else {
						None
					}
				} else {
					None
				}
			} else {
				None
			};

			let func_name = func_name.unwrap_or_else(|| format!("unknown_{j}"));

			// Check if the resolved address falls within the expected module
			let in_expected = resolved_addr >= expected_module.base_address
				&& resolved_addr < expected_module.base_address + expected_module.size as u64;

			if !in_expected {
				let actual_module = resolve_address_to_module(resolved_addr, all_modules);

				hooks.push(HookInfo {
					hook_type: HookType::IatHook,
					module: module.name.clone(),
					function: format!("{dll_name}!{func_name}"),
					address: iat_addr + iat_off as u64,
					expected_bytes: Vec::new(),
					actual_bytes: iat_data[iat_off..iat_off + thunk_entry_size].to_vec(),
					destination: Some(resolved_addr),
					destination_module: actual_module,
				});
			}
		}
	}

	Ok(())
}

// ---------------------------------------------------------------------------
// EAT hook detection
// ---------------------------------------------------------------------------

/// Detect EAT (Export Address Table) hooks in critical DLLs.
///
/// Compares the in-memory export function RVAs against the on-disk values.
/// If they differ, the export has been patched.
fn detect_eat_hooks(
	handle: HANDLE,
	modules: &[ModuleInfo],
	hooks: &mut Vec<HookInfo>,
) -> Result<()> {
	for dll_name in CRITICAL_DLLS {
		let module = match modules
			.iter()
			.find(|m| m.name.eq_ignore_ascii_case(dll_name))
		{
			Some(m) => m,
			None => continue,
		};

		if module.path.is_empty() || module.base_address == 0 {
			continue;
		}

		if let Err(e) = scan_eat_hooks(handle, module, modules, hooks) {
			tracing::debug!(
				module = %module.name,
				error = %e,
				"failed to scan module for EAT hooks, skipping"
			);
		}
	}

	Ok(())
}

/// Scan a single module for EAT hooks by comparing on-disk and in-memory exports.
fn scan_eat_hooks(
	handle: HANDLE,
	module: &ModuleInfo,
	all_modules: &[ModuleInfo],
	hooks: &mut Vec<HookInfo>,
) -> Result<()> {
	// Read on-disk DLL
	let metadata = std::fs::metadata(&module.path).map_err(MyceliumError::IoError)?;
	if metadata.len() > MAX_DLL_FILE_SIZE {
		return Err(MyceliumError::ParseError(format!(
			"DLL file too large: {} bytes",
			metadata.len()
		)));
	}

	let disk_data = std::fs::read(&module.path).map_err(MyceliumError::IoError)?;

	// Parse on-disk exports
	let disk_exports = match parse_pe_exports(&disk_data) {
		Some(e) => e,
		None => return Ok(()),
	};

	let disk_sections = match parse_pe_sections(&disk_data) {
		Some(s) => s,
		None => return Ok(()),
	};

	// Read the export directory from process memory
	let base = module.base_address;

	// Read DOS header from process
	let dos_header = match read_process_memory_safe(handle, base, 0x40) {
		Some(d) => d,
		None => return Ok(()),
	};

	let e_lfanew = match read_u32(&dos_header, 0x3C) {
		Some(v) => v as u64,
		None => return Ok(()),
	};

	// Read PE header from process
	let pe_header_addr = base + e_lfanew;
	let pe_header = match read_process_memory_safe(handle, pe_header_addr, 512) {
		Some(d) => d,
		None => return Ok(()),
	};

	if pe_header.len() < 4 || &pe_header[0..4] != b"PE\0\0" {
		return Ok(());
	}

	let optional_header_offset = 24;
	let magic = match read_u16(&pe_header, optional_header_offset) {
		Some(v) => v,
		None => return Ok(()),
	};

	let export_dir_offset = match magic {
		0x10B => optional_header_offset + 96,
		0x20B => optional_header_offset + 112,
		_ => return Ok(()),
	};

	if export_dir_offset + 8 > pe_header.len() {
		return Ok(());
	}

	let export_rva = match read_u32(&pe_header, export_dir_offset) {
		Some(v) => v,
		None => return Ok(()),
	};
	let export_size = match read_u32(&pe_header, export_dir_offset + 4) {
		Some(v) => v,
		None => return Ok(()),
	};

	if export_rva == 0 || export_size == 0 {
		return Ok(());
	}

	// Read the export directory from process memory
	let export_addr = base + export_rva as u64;
	let export_dir = match read_process_memory_safe(handle, export_addr, 40) {
		Some(d) if d.len() >= 40 => d,
		_ => return Ok(()),
	};

	let number_of_functions = match read_u32(&export_dir, 20) {
		Some(v) => v as usize,
		None => return Ok(()),
	};
	let address_of_functions_rva = match read_u32(&export_dir, 28) {
		Some(v) => v,
		None => return Ok(()),
	};

	let num_functions = number_of_functions.min(MAX_EXPORTS_PER_MODULE);

	// Read the function address array from process memory
	let func_array_addr = base + address_of_functions_rva as u64;
	let mem_func_data = match read_process_memory_safe(handle, func_array_addr, num_functions * 4) {
		Some(d) => d,
		None => return Ok(()),
	};

	// Read the function address array from disk
	let disk_func_offset = match rva_to_file_offset(address_of_functions_rva, &disk_sections) {
		Some(o) => o,
		None => return Ok(()),
	};

	// Build a map of disk export RVAs for comparison
	// The on-disk function array is at the same RVA
	let disk_func_end = disk_func_offset + num_functions * 4;
	if disk_func_end > disk_data.len() {
		return Ok(());
	}

	// Compare each function RVA
	for export in &disk_exports.functions {
		let func_name = match &export.name {
			Some(n) => n.clone(),
			None => continue,
		};

		let disk_rva = export.rva;

		// Find the index of this export in the function array by checking RVAs
		// We need the ordinal-based index into the function array
		let ordinal_base = match read_u32(&export_dir, 16) {
			Some(v) => v,
			None => continue,
		};

		// The ordinal gives us the index into the function address array
		let func_index = export.ordinal as u32 - ordinal_base;
		let mem_rva_off = func_index as usize * 4;

		if mem_rva_off + 4 > mem_func_data.len() {
			continue;
		}

		let mem_rva = match read_u32(&mem_func_data, mem_rva_off) {
			Some(v) => v,
			None => continue,
		};

		// Compare RVAs
		if mem_rva != disk_rva && mem_rva != 0 && disk_rva != 0 {
			// Determine where the in-memory RVA points
			let mem_destination = base + mem_rva as u64;
			let destination_module = resolve_address_to_module(mem_destination, all_modules);

			// Build expected/actual byte representations of the RVA
			let expected_bytes = disk_rva.to_le_bytes().to_vec();
			let actual_bytes = mem_rva.to_le_bytes().to_vec();

			hooks.push(HookInfo {
				hook_type: HookType::EatHook,
				module: module.name.clone(),
				function: func_name,
				address: func_array_addr + mem_rva_off as u64,
				expected_bytes,
				actual_bytes,
				destination: Some(mem_destination),
				destination_module,
			});
		}
	}

	Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
	use super::*;

	// -- detect_inline_hook_pattern --

	#[test]
	fn test_jmp_rel32() {
		// JMP rel32: E9 <4-byte displacement>
		// From address 0x1000, jump +0x100 → destination = 0x1000 + 5 + 0x100 = 0x1105
		let bytes = [0xE9, 0x00, 0x01, 0x00, 0x00, 0x90, 0x90, 0x90];
		let result = detect_inline_hook_pattern(&bytes, 0x1000);
		assert_eq!(result, Some(0x1105));
	}

	#[test]
	fn test_jmp_rel32_negative() {
		// JMP rel32 with negative displacement
		// E9 FB FE FF FF → displacement = -261 (0xFFFFFEFB as i32)
		// From 0x2000: destination = 0x2000 + 5 + (-261) = 0x1F00
		let bytes = [0xE9, 0xFB, 0xFE, 0xFF, 0xFF, 0x90, 0x90, 0x90];
		let result = detect_inline_hook_pattern(&bytes, 0x2000);
		assert_eq!(result, Some(0x1F00));
	}

	#[test]
	fn test_jmp_rip_disp32() {
		// JMP [rip+disp32]: FF 25 <4-byte displacement>
		// From address 0x1000, indirect address = 0x1000 + 6 + 0x10 = 0x1016
		let bytes = [0xFF, 0x25, 0x10, 0x00, 0x00, 0x00, 0x90, 0x90];
		let result = detect_inline_hook_pattern(&bytes, 0x1000);
		assert_eq!(result, Some(0x1016));
	}

	#[test]
	fn test_mov_rax_jmp_rax() {
		// mov rax, 0xDEADBEEFCAFEBABE; jmp rax
		// 48 B8 <8-byte imm64> FF E0
		let bytes = [
			0x48, 0xB8, 0xBE, 0xBA, 0xFE, 0xCA, 0xEF, 0xBE, 0xAD, 0xDE, 0xFF, 0xE0,
		];
		let result = detect_inline_hook_pattern(&bytes, 0x1000);
		assert_eq!(result, Some(0xDEADBEEFCAFEBABE));
	}

	#[test]
	fn test_push_ret() {
		// push 0x12345678; ret
		// 68 78 56 34 12 C3
		let bytes = [0x68, 0x78, 0x56, 0x34, 0x12, 0xC3, 0x90, 0x90];
		let result = detect_inline_hook_pattern(&bytes, 0x1000);
		assert_eq!(result, Some(0x12345678));
	}

	#[test]
	fn test_no_pattern_nop_sled() {
		let bytes = [0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90];
		let result = detect_inline_hook_pattern(&bytes, 0x1000);
		assert_eq!(result, None);
	}

	#[test]
	fn test_no_pattern_too_short() {
		let bytes = [0xE9, 0x00, 0x01];
		let result = detect_inline_hook_pattern(&bytes, 0x1000);
		assert_eq!(result, None);
	}

	#[test]
	fn test_no_pattern_empty() {
		let bytes: [u8; 0] = [];
		let result = detect_inline_hook_pattern(&bytes, 0x1000);
		assert_eq!(result, None);
	}

	#[test]
	fn test_mov_rax_jmp_rax_incomplete() {
		// mov rax but without the jmp rax at the right position
		let bytes = [
			0x48, 0xB8, 0xBE, 0xBA, 0xFE, 0xCA, 0xEF, 0xBE, 0xAD, 0xDE, 0x90, 0x90,
		];
		let result = detect_inline_hook_pattern(&bytes, 0x1000);
		// Should not match because bytes[10..12] != FF E0
		assert_eq!(result, None);
	}

	// -- rva_to_file_offset --

	#[test]
	fn test_rva_to_file_offset_basic() {
		let sections = vec![SectionEntry {
			name: ".text".to_string(),
			virtual_address: 0x1000,
			virtual_size: 0x2000,
			pointer_to_raw_data: 0x400,
			size_of_raw_data: 0x2000,
		}];

		// RVA 0x1100 → offset = 0x400 + (0x1100 - 0x1000) = 0x500
		assert_eq!(rva_to_file_offset(0x1100, &sections), Some(0x500));
	}

	#[test]
	fn test_rva_to_file_offset_start_of_section() {
		let sections = vec![SectionEntry {
			name: ".text".to_string(),
			virtual_address: 0x1000,
			virtual_size: 0x2000,
			pointer_to_raw_data: 0x400,
			size_of_raw_data: 0x2000,
		}];

		// RVA exactly at section start
		assert_eq!(rva_to_file_offset(0x1000, &sections), Some(0x400));
	}

	#[test]
	fn test_rva_to_file_offset_out_of_range() {
		let sections = vec![SectionEntry {
			name: ".text".to_string(),
			virtual_address: 0x1000,
			virtual_size: 0x2000,
			pointer_to_raw_data: 0x400,
			size_of_raw_data: 0x2000,
		}];

		// RVA outside any section
		assert_eq!(rva_to_file_offset(0x5000, &sections), None);
	}

	#[test]
	fn test_rva_to_file_offset_before_section() {
		let sections = vec![SectionEntry {
			name: ".text".to_string(),
			virtual_address: 0x1000,
			virtual_size: 0x2000,
			pointer_to_raw_data: 0x400,
			size_of_raw_data: 0x2000,
		}];

		// RVA before any section
		assert_eq!(rva_to_file_offset(0x500, &sections), None);
	}

	#[test]
	fn test_rva_to_file_offset_multiple_sections() {
		let sections = vec![
			SectionEntry {
				name: ".text".to_string(),
				virtual_address: 0x1000,
				virtual_size: 0x1000,
				pointer_to_raw_data: 0x400,
				size_of_raw_data: 0x1000,
			},
			SectionEntry {
				name: ".rdata".to_string(),
				virtual_address: 0x2000,
				virtual_size: 0x800,
				pointer_to_raw_data: 0x1400,
				size_of_raw_data: 0x800,
			},
		];

		// RVA in .text
		assert_eq!(rva_to_file_offset(0x1200, &sections), Some(0x600));
		// RVA in .rdata
		assert_eq!(rva_to_file_offset(0x2100, &sections), Some(0x1500));
	}

	#[test]
	fn test_rva_to_file_offset_beyond_raw_data() {
		let sections = vec![SectionEntry {
			name: ".bss".to_string(),
			virtual_address: 0x1000,
			virtual_size: 0x2000,
			pointer_to_raw_data: 0x400,
			size_of_raw_data: 0x100, // raw data is smaller than virtual size
		}];

		// RVA within virtual size but beyond raw data
		assert_eq!(rva_to_file_offset(0x1200, &sections), None);
		// RVA within raw data
		assert_eq!(rva_to_file_offset(0x1050, &sections), Some(0x450));
	}

	#[test]
	fn test_rva_to_file_offset_empty_sections() {
		let sections: Vec<SectionEntry> = Vec::new();
		assert_eq!(rva_to_file_offset(0x1000, &sections), None);
	}

	// -- has_non_relocation_diff --

	#[test]
	fn test_no_diff() {
		let mem = [0x48, 0x89, 0x5C, 0x24, 0x08];
		let disk = [0x48, 0x89, 0x5C, 0x24, 0x08];
		let relocated = HashSet::new();

		assert!(!has_non_relocation_diff(&mem, &disk, 0x1000, &relocated));
	}

	#[test]
	fn test_diff_at_relocated_address() {
		let mem = [0x48, 0x89, 0x5C, 0x24, 0xFF];
		let disk = [0x48, 0x89, 0x5C, 0x24, 0x08];
		let mut relocated = HashSet::new();
		relocated.insert(0x1004); // byte 4 is relocated

		// The diff at index 4 (RVA 0x1004) is explained by relocation
		assert!(!has_non_relocation_diff(&mem, &disk, 0x1000, &relocated));
	}

	#[test]
	fn test_diff_not_at_relocated_address() {
		let mem = [0xE9, 0x89, 0x5C, 0x24, 0x08];
		let disk = [0x48, 0x89, 0x5C, 0x24, 0x08];
		let mut relocated = HashSet::new();
		relocated.insert(0x1004); // relocation at a different byte

		// The diff at index 0 (RVA 0x1000) is NOT a relocation
		assert!(has_non_relocation_diff(&mem, &disk, 0x1000, &relocated));
	}

	#[test]
	fn test_diff_mixed_relocation_and_hook() {
		let mem = [0xE9, 0x00, 0x01, 0x00, 0xFF];
		let disk = [0x48, 0x89, 0x5C, 0x24, 0x08];
		let mut relocated = HashSet::new();
		relocated.insert(0x1004); // byte 4 is relocated

		// Byte 0 differs and is not relocated → true
		assert!(has_non_relocation_diff(&mem, &disk, 0x1000, &relocated));
	}

	#[test]
	fn test_diff_all_relocated() {
		let mem = [0xFF, 0xFF, 0xFF, 0xFF];
		let disk = [0x00, 0x00, 0x00, 0x00];
		let mut relocated = HashSet::new();
		for i in 0..4u32 {
			relocated.insert(0x1000 + i);
		}

		// All diffs are explained by relocations
		assert!(!has_non_relocation_diff(&mem, &disk, 0x1000, &relocated));
	}

	#[test]
	fn test_diff_empty_slices() {
		let mem: [u8; 0] = [];
		let disk: [u8; 0] = [];
		let relocated = HashSet::new();

		assert!(!has_non_relocation_diff(&mem, &disk, 0x1000, &relocated));
	}

	// -- parse_relocations --

	#[test]
	fn test_parse_relocations_empty() {
		let sections = vec![SectionEntry {
			name: ".text".to_string(),
			virtual_address: 0x1000,
			virtual_size: 0x1000,
			pointer_to_raw_data: 0x200,
			size_of_raw_data: 0x1000,
		}];

		// No .reloc section
		let relocated = parse_relocations(&[], &sections);
		assert!(relocated.is_empty());
	}

	#[test]
	fn test_parse_relocations_highlow() {
		// Build a minimal .reloc section with one HIGHLOW entry
		let mut data = vec![0u8; 0x200 + 12];
		let reloc_start = 0x200;

		// Block header: page RVA = 0x1000, block size = 12 (8 header + 2 entry + 2 padding)
		data[reloc_start] = 0x00;
		data[reloc_start + 1] = 0x10;
		data[reloc_start + 2] = 0x00;
		data[reloc_start + 3] = 0x00;
		data[reloc_start + 4] = 0x0C; // block size = 12
		data[reloc_start + 5] = 0x00;
		data[reloc_start + 6] = 0x00;
		data[reloc_start + 7] = 0x00;

		// Entry: type 3 (HIGHLOW), offset 0x50 → entry = 0x3050
		data[reloc_start + 8] = 0x50;
		data[reloc_start + 9] = 0x30;

		// Padding entry: type 0 (ABSOLUTE), offset 0x00
		data[reloc_start + 10] = 0x00;
		data[reloc_start + 11] = 0x00;

		let sections = vec![SectionEntry {
			name: ".reloc".to_string(),
			virtual_address: 0x3000,
			virtual_size: 0x100,
			pointer_to_raw_data: 0x200,
			size_of_raw_data: 12,
		}];

		let relocated = parse_relocations(&data, &sections);
		// HIGHLOW covers 4 bytes: 0x1050, 0x1051, 0x1052, 0x1053
		assert!(relocated.contains(&0x1050));
		assert!(relocated.contains(&0x1051));
		assert!(relocated.contains(&0x1052));
		assert!(relocated.contains(&0x1053));
		assert!(!relocated.contains(&0x1054));
	}

	#[test]
	fn test_parse_relocations_dir64() {
		let mut data = vec![0u8; 0x200 + 12];
		let reloc_start = 0x200;

		// Block header: page RVA = 0x2000, block size = 12
		data[reloc_start] = 0x00;
		data[reloc_start + 1] = 0x20;
		data[reloc_start + 4] = 0x0C;

		// Entry: type 10 (DIR64), offset 0x80 → entry = 0xA080
		data[reloc_start + 8] = 0x80;
		data[reloc_start + 9] = 0xA0;

		data[reloc_start + 10] = 0x00;
		data[reloc_start + 11] = 0x00;

		let sections = vec![SectionEntry {
			name: ".reloc".to_string(),
			virtual_address: 0x4000,
			virtual_size: 0x100,
			pointer_to_raw_data: 0x200,
			size_of_raw_data: 12,
		}];

		let relocated = parse_relocations(&data, &sections);
		// DIR64 covers 8 bytes: 0x2080..0x2087
		for i in 0..8u32 {
			assert!(relocated.contains(&(0x2080 + i)));
		}
		assert!(!relocated.contains(&0x2088));
	}

	// -- resolve_address_to_module --

	#[test]
	fn test_resolve_address_found() {
		let modules = vec![
			ModuleInfo {
				name: "ntdll.dll".to_string(),
				base_address: 0x7FF80000_0000,
				size: 0x1A0000,
				path: String::new(),
			},
			ModuleInfo {
				name: "kernel32.dll".to_string(),
				base_address: 0x7FF81000_0000,
				size: 0xB0000,
				path: String::new(),
			},
		];

		let result = resolve_address_to_module(0x7FF80000_1234, &modules);
		assert_eq!(result, Some("ntdll.dll".to_string()));

		let result = resolve_address_to_module(0x7FF81000_5678, &modules);
		assert_eq!(result, Some("kernel32.dll".to_string()));
	}

	#[test]
	fn test_resolve_address_not_found() {
		let modules = vec![ModuleInfo {
			name: "ntdll.dll".to_string(),
			base_address: 0x7FF80000_0000,
			size: 0x1000,
			path: String::new(),
		}];

		let result = resolve_address_to_module(0xDEAD_BEEF, &modules);
		assert_eq!(result, None);
	}

	#[test]
	fn test_resolve_address_at_boundary() {
		let modules = vec![ModuleInfo {
			name: "test.dll".to_string(),
			base_address: 0x1000,
			size: 0x100,
			path: String::new(),
		}];

		// Exactly at base
		assert_eq!(
			resolve_address_to_module(0x1000, &modules),
			Some("test.dll".to_string())
		);

		// Last valid address
		assert_eq!(
			resolve_address_to_module(0x10FF, &modules),
			Some("test.dll".to_string())
		);

		// Just past the end
		assert_eq!(resolve_address_to_module(0x1100, &modules), None);
	}

	// -- read_u16 / read_u32 --

	#[test]
	fn test_read_u16_basic() {
		let data = [0x34, 0x12];
		assert_eq!(read_u16(&data, 0), Some(0x1234));
	}

	#[test]
	fn test_read_u16_out_of_bounds() {
		let data = [0x34];
		assert_eq!(read_u16(&data, 0), None);
	}

	#[test]
	fn test_read_u32_basic() {
		let data = [0x78, 0x56, 0x34, 0x12];
		assert_eq!(read_u32(&data, 0), Some(0x12345678));
	}

	#[test]
	fn test_read_u32_out_of_bounds() {
		let data = [0x78, 0x56, 0x34];
		assert_eq!(read_u32(&data, 0), None);
	}

	// -- parse_pe_sections --

	#[test]
	fn test_parse_pe_sections_invalid() {
		// Too short to be a valid PE
		let data = [0u8; 16];
		assert_eq!(parse_pe_sections(&data), None);
	}

	#[test]
	fn test_parse_pe_sections_bad_signature() {
		let mut data = vec![0u8; 512];
		// e_lfanew at 0x3C pointing to offset 0x80
		data[0x3C] = 0x80;
		// Wrong PE signature
		data[0x80] = b'X';
		data[0x81] = b'X';

		assert_eq!(parse_pe_sections(&data), None);
	}
}
