//! Process management via sysinfo.

use std::time::SystemTime;

use sysinfo::{Pid, ProcessStatus, ProcessesToUpdate, System};

use mycelium_core::error::{MyceliumError, Result};
use mycelium_core::types::{ProcessInfo, ProcessResource, ProcessState, Signal};

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

fn boot_time_secs() -> u64 {
	System::boot_time()
}

fn build_process_info(proc: &sysinfo::Process) -> ProcessInfo {
	let cmd = proc.cmd().join(" ");
	let start = proc.start_time();

	ProcessInfo {
		pid: proc.pid().as_u32(),
		ppid: proc.parent().map(|p| p.as_u32()).unwrap_or(0),
		name: proc.name().to_string_lossy().to_string(),
		state: map_process_state(proc.status()),
		user: String::new(),
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
		open_fds: 0, // not available via sysinfo on Windows
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
