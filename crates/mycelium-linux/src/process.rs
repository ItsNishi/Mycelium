//! Process queries and control via /proc and signals.

use mycelium_core::error::{MyceliumError, Result};
use mycelium_core::types::{ProcessInfo, ProcessResource, ProcessState, Signal};
use std::fs;
use std::path::Path;

/// Read the total system memory from /proc/meminfo (for memory percent calc).
fn total_memory_bytes() -> u64 {
	fs::read_to_string("/proc/meminfo")
		.ok()
		.and_then(|s| {
			s.lines()
				.find(|l| l.starts_with("MemTotal:"))
				.and_then(|l| l.split_whitespace().nth(1))
				.and_then(|v| v.parse::<u64>().ok())
				.map(|kb| kb * 1024)
		})
		.unwrap_or(1)
}

/// Parse /proc/[pid]/stat into fields.
fn parse_stat(pid: u32) -> Result<Vec<String>> {
	let path = format!("/proc/{pid}/stat");
	let content = fs::read_to_string(&path).map_err(|e| {
		if e.kind() == std::io::ErrorKind::NotFound {
			MyceliumError::NotFound(format!("process {pid}"))
		} else if e.kind() == std::io::ErrorKind::PermissionDenied {
			MyceliumError::PermissionDenied(format!("cannot read {path}"))
		} else {
			MyceliumError::IoError(e)
		}
	})?;

	// comm field can contain spaces and parens, so parse around it
	let open = content
		.find('(')
		.ok_or_else(|| MyceliumError::ParseError(format!("malformed stat for pid {pid}")))?;
	let close = content
		.rfind(')')
		.ok_or_else(|| MyceliumError::ParseError(format!("malformed stat for pid {pid}")))?;

	let mut fields = Vec::with_capacity(52);
	fields.push(content[..open].trim().to_string()); // pid
	fields.push(content[open + 1..close].to_string()); // comm
	for field in content[close + 2..].split_whitespace() {
		fields.push(field.to_string());
	}
	Ok(fields)
}

fn parse_state(ch: &str) -> ProcessState {
	match ch {
		"R" => ProcessState::Running,
		"S" => ProcessState::Sleeping,
		"D" => ProcessState::DiskSleep,
		"T" | "t" => ProcessState::Stopped,
		"Z" => ProcessState::Zombie,
		"X" | "x" => ProcessState::Dead,
		_ => ProcessState::Unknown,
	}
}

fn uid_for_pid(pid: u32) -> u32 {
	fs::read_to_string(format!("/proc/{pid}/status"))
		.ok()
		.and_then(|s| {
			s.lines()
				.find(|l| l.starts_with("Uid:"))
				.and_then(|l| l.split_whitespace().nth(1))
				.and_then(|v| v.parse().ok())
		})
		.unwrap_or(0)
}

fn username_for_uid(uid: u32) -> String {
	nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
		.ok()
		.flatten()
		.map(|u| u.name)
		.unwrap_or_else(|| uid.to_string())
}

fn thread_count(pid: u32) -> u32 {
	fs::read_to_string(format!("/proc/{pid}/status"))
		.ok()
		.and_then(|s| {
			s.lines()
				.find(|l| l.starts_with("Threads:"))
				.and_then(|l| l.split_whitespace().nth(1))
				.and_then(|v| v.parse().ok())
		})
		.unwrap_or(1)
}

fn cmdline(pid: u32) -> String {
	fs::read_to_string(format!("/proc/{pid}/cmdline"))
		.ok()
		.map(|s| s.replace('\0', " ").trim().to_string())
		.unwrap_or_default()
}

fn rss_bytes_from_stat(fields: &[String]) -> u64 {
	// Field index 23 is rss in pages
	let page_size = nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE)
		.ok()
		.flatten()
		.unwrap_or(4096) as u64;
	fields
		.get(23)
		.and_then(|v| v.parse::<u64>().ok())
		.unwrap_or(0)
		* page_size
}

fn start_time_from_stat(fields: &[String]) -> u64 {
	// Field index 21 is starttime in clock ticks since boot
	let ticks_per_sec = nix::unistd::sysconf(nix::unistd::SysconfVar::CLK_TCK)
		.ok()
		.flatten()
		.unwrap_or(100) as u64;
	let start_ticks = fields
		.get(21)
		.and_then(|v| v.parse::<u64>().ok())
		.unwrap_or(0);

	// Get boot time
	let boot_time = fs::read_to_string("/proc/stat")
		.ok()
		.and_then(|s| {
			s.lines()
				.find(|l| l.starts_with("btime "))
				.and_then(|l| l.split_whitespace().nth(1))
				.and_then(|v| v.parse::<u64>().ok())
		})
		.unwrap_or(0);

	boot_time + start_ticks / ticks_per_sec
}

fn build_process_info(pid: u32) -> Result<ProcessInfo> {
	let fields = parse_stat(pid)?;
	let uid = uid_for_pid(pid);

	let ppid = fields
		.get(3)
		.and_then(|v| v.parse().ok())
		.unwrap_or(0);
	let state = fields
		.get(2)
		.map(|s| parse_state(s))
		.unwrap_or(ProcessState::Unknown);
	let threads = thread_count(pid);
	let mem = rss_bytes_from_stat(&fields);

	Ok(ProcessInfo {
		pid,
		ppid,
		name: fields.get(1).cloned().unwrap_or_default(),
		state,
		user: username_for_uid(uid),
		uid,
		threads,
		cpu_percent: 0.0, // Snapshot -- would need two reads for real %
		memory_bytes: mem,
		command: cmdline(pid),
		start_time: start_time_from_stat(&fields),
	})
}

pub fn list_processes() -> Result<Vec<ProcessInfo>> {
	let mut processes = Vec::new();
	for entry in fs::read_dir("/proc")? {
		let entry = entry?;
		let name = entry.file_name();
		let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
			continue;
		};
		// Skip processes we can't read (permission issues)
		if let Ok(info) = build_process_info(pid) {
			processes.push(info);
		}
	}
	processes.sort_by_key(|p| p.pid);
	Ok(processes)
}

pub fn inspect_process(pid: u32) -> Result<ProcessInfo> {
	if !Path::new(&format!("/proc/{pid}")).exists() {
		return Err(MyceliumError::NotFound(format!("process {pid}")));
	}
	build_process_info(pid)
}

pub fn process_resources(pid: u32) -> Result<ProcessResource> {
	if !Path::new(&format!("/proc/{pid}")).exists() {
		return Err(MyceliumError::NotFound(format!("process {pid}")));
	}

	let fields = parse_stat(pid)?;
	let mem = rss_bytes_from_stat(&fields);
	let total_mem = total_memory_bytes();
	let vsize = fields
		.get(22)
		.and_then(|v| v.parse::<u64>().ok())
		.unwrap_or(0);
	let threads = thread_count(pid);

	// Open file descriptors
	let open_fds = fs::read_dir(format!("/proc/{pid}/fd"))
		.map(|d| d.count() as u32)
		.unwrap_or(0);

	// I/O bytes from /proc/[pid]/io
	let (read_bytes, write_bytes) =
		fs::read_to_string(format!("/proc/{pid}/io"))
			.ok()
			.map(|s| {
				let mut rb = 0u64;
				let mut wb = 0u64;
				for line in s.lines() {
					if let Some(v) = line.strip_prefix("read_bytes: ") {
						rb = v.trim().parse().unwrap_or(0);
					} else if let Some(v) = line.strip_prefix("write_bytes: ") {
						wb = v.trim().parse().unwrap_or(0);
					}
				}
				(rb, wb)
			})
			.unwrap_or((0, 0));

	Ok(ProcessResource {
		pid,
		cpu_percent: 0.0,
		memory_bytes: mem,
		memory_percent: if total_mem > 0 {
			(mem as f64 / total_mem as f64) * 100.0
		} else {
			0.0
		},
		virtual_memory_bytes: vsize,
		open_fds,
		threads,
		read_bytes,
		write_bytes,
	})
}

pub fn kill_process(pid: u32, signal: Signal) -> Result<()> {
	use nix::errno::Errno;

	let nix_sig = match signal {
		Signal::Term => nix::sys::signal::Signal::SIGTERM,
		Signal::Kill => nix::sys::signal::Signal::SIGKILL,
		Signal::Hup => nix::sys::signal::Signal::SIGHUP,
		Signal::Int => nix::sys::signal::Signal::SIGINT,
		Signal::Usr1 => nix::sys::signal::Signal::SIGUSR1,
		Signal::Usr2 => nix::sys::signal::Signal::SIGUSR2,
		Signal::Stop => nix::sys::signal::Signal::SIGSTOP,
		Signal::Cont => nix::sys::signal::Signal::SIGCONT,
	};

	nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), nix_sig).map_err(
		|e| match e {
			Errno::ESRCH => MyceliumError::NotFound(format!("process {pid}")),
			Errno::EPERM => MyceliumError::PermissionDenied(format!(
				"cannot signal process {pid}"
			)),
			_ => MyceliumError::OsError {
				code: e as i32,
				message: format!("failed to send {signal:?} to pid {pid}: {e}"),
			},
		},
	)
}
