//! Process management via sysinfo and WinAPI.

use std::mem;

use sysinfo::{Pid, ProcessStatus, ProcessesToUpdate, System};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{
	GetTokenInformation, LookupAccountSidW, TokenUser, TOKEN_QUERY, TOKEN_USER, SID_NAME_USE,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
	CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32, TH32CS_SNAPTHREAD,
};
use windows::Win32::System::ProcessStatus::{
	EnumProcessModules, GetModuleFileNameExW, GetModuleInformation, MODULEINFO,
};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Threading::{
	GetProcessHandleCount, OpenProcess, OpenProcessToken, PROCESS_BASIC_INFORMATION,
	PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};
use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation};
use windows::core::PWSTR;

use mycelium_core::error::{MyceliumError, Result};
use mycelium_core::types::{
	ProcessInfo, ProcessModule, ProcessResource, ProcessState, Signal, ThreadInfo,
};

/// Maximum number of threads to enumerate per process.
const MAX_THREADS: usize = 10_000;

/// Maximum number of modules to enumerate per process.
const MAX_MODULES: usize = 4_096;

fn get_process_owner(pid: u32) -> String {
	unsafe {
		let process = match OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) {
			Ok(h) => h,
			Err(_) => return String::new(),
		};

		let mut token = HANDLE::default();
		if OpenProcessToken(process, TOKEN_QUERY, &mut token).is_err() {
			let _ = CloseHandle(process);
			return String::new();
		}

		// Query required buffer size
		let mut size = 0u32;
		let _ = GetTokenInformation(token, TokenUser, None, 0, &mut size);
		if size == 0 {
			let _ = CloseHandle(token);
			let _ = CloseHandle(process);
			return String::new();
		}

		let mut buffer = vec![0u8; size as usize];
		if GetTokenInformation(
			token,
			TokenUser,
			Some(buffer.as_mut_ptr().cast()),
			size,
			&mut size,
		)
		.is_err()
		{
			let _ = CloseHandle(token);
			let _ = CloseHandle(process);
			return String::new();
		}

		let token_user = &*(buffer.as_ptr() as *const TOKEN_USER);
		let sid = token_user.User.Sid;

		let mut name_buf = [0u16; 256];
		let mut domain_buf = [0u16; 256];
		let mut name_len = name_buf.len() as u32;
		let mut domain_len = domain_buf.len() as u32;
		let mut sid_use = SID_NAME_USE::default();

		let result = if LookupAccountSidW(
			None,
			sid,
			Some(PWSTR(name_buf.as_mut_ptr())),
			&mut name_len,
			Some(PWSTR(domain_buf.as_mut_ptr())),
			&mut domain_len,
			&mut sid_use,
		)
		.is_ok()
		{
			let domain = String::from_utf16_lossy(&domain_buf[..domain_len as usize]);
			let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
			if domain.is_empty() {
				name
			} else {
				format!("{domain}\\{name}")
			}
		} else {
			String::new()
		};

		let _ = CloseHandle(token);
		let _ = CloseHandle(process);
		result
	}
}

fn get_handle_count(pid: u32) -> u32 {
	unsafe {
		let process = match OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) {
			Ok(h) => h,
			Err(_) => return 0,
		};

		let mut count = 0u32;
		let ok = GetProcessHandleCount(process, &mut count);
		let _ = CloseHandle(process);
		if ok.is_ok() {
			count
		} else {
			0
		}
	}
}

fn map_process_state(status: ProcessStatus) -> ProcessState {
	match status {
		ProcessStatus::Run => ProcessState::Running,
		ProcessStatus::Stop => ProcessState::Stopped,
		ProcessStatus::Zombie => ProcessState::Zombie,
		ProcessStatus::Dead => ProcessState::Dead,
		ProcessStatus::Sleep | ProcessStatus::Idle => ProcessState::Sleeping,
		_ => ProcessState::Unknown,
	}
}

fn build_process_info(proc: &sysinfo::Process) -> ProcessInfo {
	let cmd: String = proc
		.cmd()
		.iter()
		.map(|s| s.to_string_lossy())
		.collect::<Vec<_>>()
		.join(" ");
	let start = proc.start_time();

	ProcessInfo {
		pid: proc.pid().as_u32(),
		ppid: proc.parent().map(|p| p.as_u32()).unwrap_or(0),
		name: proc.name().to_string_lossy().to_string(),
		state: map_process_state(proc.status()),
		user: get_process_owner(proc.pid().as_u32()),
		uid: 0,
		threads: proc.tasks().map(|t| t.len() as u32).unwrap_or(0),
		cpu_percent: proc.cpu_usage() as f64,
		memory_bytes: proc.memory(),
		command: if cmd.is_empty() {
			proc.name().to_string_lossy().to_string()
		} else {
			cmd
		},
		start_time: start,
	}
}

pub fn list_processes() -> Result<Vec<ProcessInfo>> {
	let mut sys = System::new();
	sys.refresh_processes(ProcessesToUpdate::All, true);

	let procs = sys
		.processes()
		.values()
		.map(build_process_info)
		.collect();
	Ok(procs)
}

pub fn inspect_process(pid: u32) -> Result<ProcessInfo> {
	let mut sys = System::new();
	let sysinfo_pid = Pid::from_u32(pid);
	sys.refresh_processes(ProcessesToUpdate::Some(&[sysinfo_pid]), true);

	sys.process(sysinfo_pid)
		.map(build_process_info)
		.ok_or_else(|| MyceliumError::NotFound(format!("process {pid}")))
}

pub fn process_resources(pid: u32) -> Result<ProcessResource> {
	let mut sys = System::new();
	let sysinfo_pid = Pid::from_u32(pid);
	sys.refresh_processes(ProcessesToUpdate::Some(&[sysinfo_pid]), true);
	sys.refresh_memory();

	let proc = sys
		.process(sysinfo_pid)
		.ok_or_else(|| MyceliumError::NotFound(format!("process {pid}")))?;

	let total_mem = sys.total_memory();
	let mem = proc.memory();
	let mem_percent = if total_mem > 0 {
		(mem as f64 / total_mem as f64) * 100.0
	} else {
		0.0
	};

	let disk = proc.disk_usage();

	Ok(ProcessResource {
		pid,
		cpu_percent: proc.cpu_usage() as f64,
		memory_bytes: mem,
		memory_percent: mem_percent,
		virtual_memory_bytes: proc.virtual_memory(),
		open_fds: get_handle_count(pid),
		threads: proc.tasks().map(|t| t.len() as u32).unwrap_or(0),
		read_bytes: disk.read_bytes,
		write_bytes: disk.written_bytes,
	})
}

pub fn kill_process(pid: u32, signal: Signal) -> Result<()> {
	match signal {
		Signal::Term | Signal::Kill | Signal::Int => {}
		other => {
			return Err(MyceliumError::Unsupported(format!(
				"signal {other:?} is not supported on Windows"
			)));
		}
	}

	let mut sys = System::new();
	let sysinfo_pid = Pid::from_u32(pid);
	sys.refresh_processes(ProcessesToUpdate::Some(&[sysinfo_pid]), true);

	let proc = sys
		.process(sysinfo_pid)
		.ok_or_else(|| MyceliumError::NotFound(format!("process {pid}")))?;

	if proc.kill() {
		Ok(())
	} else {
		Err(MyceliumError::PermissionDenied(format!(
			"failed to terminate process {pid}"
		)))
	}
}

pub fn list_process_threads(pid: u32) -> Result<Vec<ThreadInfo>> {
	let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }.map_err(|e| {
		MyceliumError::OsError {
			code: e.code().0,
			message: format!("CreateToolhelp32Snapshot failed: {e}"),
		}
	})?;

	let mut entry = THREADENTRY32 {
		dwSize: mem::size_of::<THREADENTRY32>() as u32,
		..Default::default()
	};

	let mut threads = Vec::new();

	let ok = unsafe { Thread32First(snapshot, &mut entry) };
	if ok.is_err() {
		unsafe {
			let _ = CloseHandle(snapshot);
		}
		return Ok(threads);
	}

	loop {
		if entry.th32OwnerProcessID == pid {
			threads.push(ThreadInfo {
				tid: entry.th32ThreadID,
				pid: entry.th32OwnerProcessID,
				priority: entry.tpBasePri,
			});
			if threads.len() >= MAX_THREADS {
				break;
			}
		}

		entry.dwSize = mem::size_of::<THREADENTRY32>() as u32;
		if unsafe { Thread32Next(snapshot, &mut entry) }.is_err() {
			break;
		}
	}

	unsafe {
		let _ = CloseHandle(snapshot);
	}
	Ok(threads)
}

pub fn list_process_modules(pid: u32) -> Result<Vec<ProcessModule>> {
	let _ = crate::privilege::ensure_debug_privilege();

	let handle = unsafe {
		OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
	}
	.map_err(|e| {
		MyceliumError::PermissionDenied(format!("cannot open process {pid}: {e}"))
	})?;

	let result = enumerate_modules(handle);
	unsafe {
		let _ = CloseHandle(handle);
	}
	result
}

fn enumerate_modules(handle: HANDLE) -> Result<Vec<ProcessModule>> {
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

	let count =
		cb_needed as usize / mem::size_of::<windows::Win32::Foundation::HMODULE>();
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
			(mod_info.lpBaseOfDll as u64, mod_info.SizeOfImage as u64)
		} else {
			(0, 0)
		};

		modules.push(ProcessModule {
			name,
			path,
			base_address,
			size,
		});
	}

	Ok(modules)
}

/// Maximum bytes to read for the environment block (256 KiB).
const MAX_ENV_SIZE: usize = 256 * 1024;

/// Find the position of a double-null terminator in a u16 slice.
fn find_double_null_u16(data: &[u16]) -> Option<usize> {
	data.windows(2).position(|w| w[0] == 0 && w[1] == 0)
}

/// Parse a UTF-16LE environment block (null-separated KEY=VALUE pairs) into Vec<(K, V)>.
fn parse_env_block_utf16(data: &[u16]) -> Vec<(String, String)> {
	let mut result = Vec::new();
	let mut start = 0;

	for i in 0..data.len() {
		if data[i] == 0 {
			if i == start {
				break; // empty string means end
			}
			let entry = String::from_utf16_lossy(&data[start..i]);
			// Skip internal Windows vars like `=C:`
			if !entry.starts_with('=')
				&& let Some((k, v)) = entry.split_once('=')
			{
				result.push((k.to_string(), v.to_string()));
			}
			start = i + 1;
		}
	}

	result
}

/// Read the environment variables of a process via PEB traversal.
fn read_process_env(handle: HANDLE) -> Result<Vec<(String, String)>> {
	// 1. Get PEB address via NtQueryInformationProcess
	let mut pbi: PROCESS_BASIC_INFORMATION = unsafe { mem::zeroed() };
	let mut return_length: u32 = 0;
	let status = unsafe {
		NtQueryInformationProcess(
			handle,
			ProcessBasicInformation,
			&mut pbi as *mut _ as *mut _,
			mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
			&mut return_length,
		)
	};

	if status.is_err() {
		return Err(MyceliumError::OsError {
			code: status.0,
			message: format!("NtQueryInformationProcess failed: {status:?}"),
		});
	}

	let peb_addr = pbi.PebBaseAddress as usize;
	if peb_addr == 0 {
		return Err(MyceliumError::OsError {
			code: -1,
			message: "PEB address is null".to_string(),
		});
	}

	// 2. Read ProcessParameters pointer from PEB + 0x20 (x64)
	let params_ptr_addr = peb_addr + 0x20;
	let mut params_ptr: usize = 0;
	let mut bytes_read: usize = 0;

	unsafe {
		ReadProcessMemory(
			handle,
			params_ptr_addr as *const _,
			&mut params_ptr as *mut _ as *mut _,
			mem::size_of::<usize>(),
			Some(&mut bytes_read),
		)
	}
	.map_err(|e| MyceliumError::OsError {
		code: e.code().0,
		message: format!("ReadProcessMemory (ProcessParameters ptr) failed: {e}"),
	})?;

	if params_ptr == 0 {
		return Ok(Vec::new());
	}

	// 3. Read Environment pointer from ProcessParameters + 0x80 (x64)
	let env_ptr_addr = params_ptr + 0x80;
	let mut env_ptr: usize = 0;

	unsafe {
		ReadProcessMemory(
			handle,
			env_ptr_addr as *const _,
			&mut env_ptr as *mut _ as *mut _,
			mem::size_of::<usize>(),
			Some(&mut bytes_read),
		)
	}
	.map_err(|e| MyceliumError::OsError {
		code: e.code().0,
		message: format!("ReadProcessMemory (Environment ptr) failed: {e}"),
	})?;

	if env_ptr == 0 {
		return Ok(Vec::new());
	}

	// 4. Read environment block (up to MAX_ENV_SIZE bytes)
	let mut buffer = vec![0u8; MAX_ENV_SIZE];
	let read_ok = unsafe {
		ReadProcessMemory(
			handle,
			env_ptr as *const _,
			buffer.as_mut_ptr() as *mut _,
			MAX_ENV_SIZE,
			Some(&mut bytes_read),
		)
	};

	if read_ok.is_err() || bytes_read == 0 {
		return Ok(Vec::new());
	}

	buffer.truncate(bytes_read);

	// Convert to u16 slice
	let u16_data: Vec<u16> = buffer
		.chunks_exact(2)
		.map(|c| u16::from_le_bytes([c[0], c[1]]))
		.collect();

	// Find double-null terminator
	let end = find_double_null_u16(&u16_data).unwrap_or(u16_data.len());
	let env_data = &u16_data[..end + 1]; // include the first null

	Ok(parse_env_block_utf16(env_data))
}

pub fn process_environment(pid: u32) -> Result<Vec<(String, String)>> {
	let _ = crate::privilege::ensure_debug_privilege();

	let handle = unsafe {
		OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
	}
	.map_err(|e| {
		MyceliumError::PermissionDenied(format!("cannot open process {pid}: {e}"))
	})?;

	let result = read_process_env(handle);
	unsafe {
		let _ = CloseHandle(handle);
	}
	result
}

#[cfg(test)]
mod tests {
	use super::*;

	// -- find_double_null_u16 --

	#[test]
	fn test_find_double_null_at_start() {
		assert_eq!(find_double_null_u16(&[0, 0, 65, 66]), Some(0));
	}

	#[test]
	fn test_find_double_null_in_middle() {
		assert_eq!(find_double_null_u16(&[65, 0, 0, 66]), Some(1));
	}

	#[test]
	fn test_find_double_null_at_end() {
		assert_eq!(find_double_null_u16(&[65, 66, 0, 0]), Some(2));
	}

	#[test]
	fn test_find_double_null_none() {
		assert_eq!(find_double_null_u16(&[65, 0, 66, 0, 67]), None);
	}

	#[test]
	fn test_find_double_null_empty() {
		assert_eq!(find_double_null_u16(&[]), None);
	}

	#[test]
	fn test_find_double_null_single_element() {
		assert_eq!(find_double_null_u16(&[0]), None);
	}

	#[test]
	fn test_find_double_null_single_zero_pair() {
		assert_eq!(find_double_null_u16(&[0, 0]), Some(0));
	}

	// -- parse_env_block_utf16 --

	/// Helper: encode a string as UTF-16LE u16 slice.
	fn to_u16(s: &str) -> Vec<u16> {
		s.encode_utf16().collect()
	}

	/// Build a UTF-16 env block from KEY=VALUE pairs, null-separated, double-null terminated.
	fn build_env_block(pairs: &[&str]) -> Vec<u16> {
		let mut block = Vec::new();
		for pair in pairs {
			block.extend(to_u16(pair));
			block.push(0); // null terminator
		}
		block.push(0); // double null
		block
	}

	#[test]
	fn test_parse_env_block_simple() {
		let block = build_env_block(&["FOO=bar", "BAZ=qux"]);
		let result = parse_env_block_utf16(&block);
		assert_eq!(result, vec![
			("FOO".to_string(), "bar".to_string()),
			("BAZ".to_string(), "qux".to_string()),
		]);
	}

	#[test]
	fn test_parse_env_block_skips_internal_vars() {
		let block = build_env_block(&["=C:=C:\\Windows", "PATH=C:\\bin", "=ExitCode=0"]);
		let result = parse_env_block_utf16(&block);
		assert_eq!(result, vec![("PATH".to_string(), "C:\\bin".to_string())]);
	}

	#[test]
	fn test_parse_env_block_empty() {
		let block = vec![0u16]; // just a null = empty block
		let result = parse_env_block_utf16(&block);
		assert!(result.is_empty());
	}

	#[test]
	fn test_parse_env_block_value_with_equals() {
		// VALUE can contain '='
		let block = build_env_block(&["KEY=a=b=c"]);
		let result = parse_env_block_utf16(&block);
		assert_eq!(result, vec![("KEY".to_string(), "a=b=c".to_string())]);
	}

	#[test]
	fn test_parse_env_block_no_equals_skipped() {
		// Entries without '=' should be skipped
		let block = build_env_block(&["NOEQUALS", "GOOD=yes"]);
		let result = parse_env_block_utf16(&block);
		assert_eq!(result, vec![("GOOD".to_string(), "yes".to_string())]);
	}

	#[test]
	fn test_parse_env_block_empty_value() {
		let block = build_env_block(&["KEY="]);
		let result = parse_env_block_utf16(&block);
		assert_eq!(result, vec![("KEY".to_string(), String::new())]);
	}
}
