//! Memory information via sysinfo and WinAPI.

use std::mem;
use std::ptr;

use sysinfo::{Pid, ProcessesToUpdate, System};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::ProcessStatus::GetMappedFileNameW;
use windows::Win32::System::Threading::{
	OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
	PROCESS_VM_WRITE,
};

use mycelium_core::error::{MyceliumError, Result};
use mycelium_core::types::{MemoryInfo, MemoryRegion, ProcessMemory, SwapInfo};

pub fn memory_info() -> Result<MemoryInfo> {
	let mut sys = System::new();
	sys.refresh_memory();

	Ok(MemoryInfo {
		total_bytes: sys.total_memory(),
		available_bytes: sys.available_memory(),
		used_bytes: sys.used_memory(),
		free_bytes: sys.free_memory(),
		buffers_bytes: 0, // Linux-specific
		cached_bytes: 0,  // Linux-specific
		swap: SwapInfo {
			total_bytes: sys.total_swap(),
			used_bytes: sys.used_swap(),
			free_bytes: sys.free_swap(),
		},
	})
}

pub fn process_memory(pid: u32) -> Result<ProcessMemory> {
	let mut sys = System::new();
	let sysinfo_pid = Pid::from_u32(pid);
	sys.refresh_processes(ProcessesToUpdate::Some(&[sysinfo_pid]), true);

	let proc = sys
		.process(sysinfo_pid)
		.ok_or_else(|| MyceliumError::NotFound(format!("process {pid}")))?;

	Ok(ProcessMemory {
		pid,
		rss_bytes: proc.memory(),
		virtual_bytes: proc.virtual_memory(),
		shared_bytes: 0,
		text_bytes: 0,
		data_bytes: 0,
	})
}

/// Memory protection constant values (from winnt.h).
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_WRITECOPY: u32 = 0x08;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
const PAGE_GUARD: u32 = 0x100;

/// Memory state constants.
const MEM_COMMIT: u32 = 0x1000;

fn protection_to_string(protect: u32) -> String {
	let base = protect & !(PAGE_GUARD);
	let perms = match base {
		PAGE_NOACCESS => "---",
		PAGE_READONLY => "r--",
		PAGE_READWRITE | PAGE_WRITECOPY => "rw-",
		PAGE_EXECUTE => "--x",
		PAGE_EXECUTE_READ => "r-x",
		PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY => "rwx",
		_ => "---",
	};
	if protect & PAGE_GUARD != 0 {
		format!("{perms}g")
	} else {
		format!("{perms}-")
	}
}

/// MEMORY_BASIC_INFORMATION for VirtualQueryEx.
#[repr(C)]
struct MemoryBasicInformation {
	base_address: usize,
	allocation_base: usize,
	allocation_protect: u32,
	_partition_id: u16,
	region_size: usize,
	state: u32,
	protect: u32,
	type_: u32,
}

pub fn process_memory_maps(pid: u32) -> Result<Vec<MemoryRegion>> {
	unsafe {
		let handle = OpenProcess(
			PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			false,
			pid,
		)
		.map_err(|e| MyceliumError::PermissionDenied(format!(
			"cannot open process {pid}: {e}"
		)))?;

		let result = enumerate_regions(handle, pid);
		let _ = CloseHandle(handle);
		result
	}
}

unsafe fn enumerate_regions(handle: HANDLE, _pid: u32) -> Result<Vec<MemoryRegion>> {
	let mut regions = Vec::new();
	let mut address: usize = 0;
	let mut mbi: MemoryBasicInformation = mem::zeroed();
	let mbi_size = mem::size_of::<MemoryBasicInformation>();

	loop {
		let written = windows::Win32::System::Threading::VirtualQueryEx(
			Some(handle),
			Some(address as *const _),
			&mut mbi as *mut _ as *mut _,
			mbi_size,
		);

		if written == 0 {
			break;
		}

		if mbi.state == MEM_COMMIT {
			let start = mbi.base_address as u64;
			let end = start + mbi.region_size as u64;

			// Try to get mapped file name
			let mut name_buf = [0u16; 260];
			let name_len = GetMappedFileNameW(
				handle,
				address as *const _,
				&mut name_buf,
			);
			let pathname = if name_len > 0 {
				Some(String::from_utf16_lossy(&name_buf[..name_len as usize]))
			} else {
				None
			};

			regions.push(MemoryRegion {
				start_address: start,
				end_address: end,
				permissions: protection_to_string(mbi.protect),
				offset: 0,
				device: "0:0".to_string(),
				inode: 0,
				pathname,
			});
		}

		address = mbi.base_address + mbi.region_size;
		if address <= mbi.base_address {
			break; // overflow guard
		}
	}

	Ok(regions)
}

pub fn read_process_memory(pid: u32, address: u64, size: usize) -> Result<Vec<u8>> {
	unsafe {
		let handle = OpenProcess(PROCESS_VM_READ, false, pid)
			.map_err(|e| MyceliumError::PermissionDenied(format!(
				"cannot open process {pid}: {e}"
			)))?;

		let mut buffer = vec![0u8; size];
		let mut bytes_read: usize = 0;

		let ok = windows::Win32::System::Threading::ReadProcessMemory(
			handle,
			address as *const _,
			buffer.as_mut_ptr() as *mut _,
			size,
			Some(&mut bytes_read),
		);

		let _ = CloseHandle(handle);

		ok.map_err(|e| MyceliumError::OsError {
			code: e.code().0,
			message: format!("ReadProcessMemory failed: {e}"),
		})?;

		buffer.truncate(bytes_read);
		Ok(buffer)
	}
}

pub fn write_process_memory(pid: u32, address: u64, data: &[u8]) -> Result<usize> {
	unsafe {
		let handle = OpenProcess(
			PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
			false,
			pid,
		)
		.map_err(|e| MyceliumError::PermissionDenied(format!(
			"cannot open process {pid}: {e}"
		)))?;

		let mut bytes_written: usize = 0;

		let ok = windows::Win32::System::Threading::WriteProcessMemory(
			handle,
			address as *const _,
			data.as_ptr() as *const _,
			data.len(),
			Some(&mut bytes_written),
		);

		let _ = CloseHandle(handle);

		ok.map_err(|e| MyceliumError::OsError {
			code: e.code().0,
			message: format!("WriteProcessMemory failed: {e}"),
		})?;

		Ok(bytes_written)
	}
}
