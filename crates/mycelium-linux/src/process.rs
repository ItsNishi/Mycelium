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

/// Parse the content of a /proc/[pid]/stat file into fields.
fn parse_stat_content(content: &str, pid: u32) -> Result<Vec<String>> {
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
	parse_stat_content(&content, pid)
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

fn parse_cmdline_content(content: &str) -> String {
	content.replace('\0', " ").trim().to_string()
}

fn cmdline(pid: u32) -> String {
	fs::read_to_string(format!("/proc/{pid}/cmdline"))
		.ok()
		.map(|s| parse_cmdline_content(&s))
		.unwrap_or_default()
}

fn parse_proc_io(content: &str) -> (u64, u64) {
	let mut rb = 0u64;
	let mut wb = 0u64;
	for line in content.lines() {
		if let Some(v) = line.strip_prefix("read_bytes: ") {
			rb = v.trim().parse().unwrap_or(0);
		} else if let Some(v) = line.strip_prefix("write_bytes: ") {
			wb = v.trim().parse().unwrap_or(0);
		}
	}
	(rb, wb)
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
			.map(|s| parse_proc_io(&s))
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

	if pid == 0 {
		return Err(MyceliumError::ParseError(
			"cannot signal PID 0 (kernel scheduler)".into(),
		));
	}
	if pid > i32::MAX as u32 {
		return Err(MyceliumError::ParseError(format!(
			"PID {pid} exceeds maximum valid PID"
		)));
	}

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

#[cfg(test)]
mod tests {
	use super::*;

	// parse_stat_content tests

	#[test]
	fn test_parse_stat_content_normal() {
		let content = "42 (bash) S 1 42 42 0 -1 4194560 1234 0 0 0 10 5 0 0 20 0 1 0 \
			100 12345678 500 18446744073709551615";
		let fields = parse_stat_content(content, 42).unwrap();
		assert_eq!(fields[0], "42");
		assert_eq!(fields[1], "bash");
		assert_eq!(fields[2], "S");
	}

	#[test]
	fn test_parse_stat_content_name_with_spaces() {
		let content = "42 (Web Content) S 1 42 42 0 -1 4194560";
		let fields = parse_stat_content(content, 42).unwrap();
		assert_eq!(fields[0], "42");
		assert_eq!(fields[1], "Web Content");
		assert_eq!(fields[2], "S");
	}

	#[test]
	fn test_parse_stat_content_nested_parens() {
		let content = "99 (kworker/0:1 (idle)) S 2 0 0 0 -1 69238880";
		let fields = parse_stat_content(content, 99).unwrap();
		assert_eq!(fields[0], "99");
		assert_eq!(fields[1], "kworker/0:1 (idle)");
		assert_eq!(fields[2], "S");
	}

	#[test]
	fn test_parse_stat_content_missing_parens() {
		let content = "42 bash S 1 42";
		assert!(parse_stat_content(content, 42).is_err());
	}

	#[test]
	fn test_parse_stat_content_empty() {
		assert!(parse_stat_content("", 1).is_err());
	}

	// parse_state tests

	#[test]
	fn test_parse_state_all_valid() {
		assert_eq!(parse_state("R"), ProcessState::Running);
		assert_eq!(parse_state("S"), ProcessState::Sleeping);
		assert_eq!(parse_state("D"), ProcessState::DiskSleep);
		assert_eq!(parse_state("T"), ProcessState::Stopped);
		assert_eq!(parse_state("t"), ProcessState::Stopped);
		assert_eq!(parse_state("Z"), ProcessState::Zombie);
		assert_eq!(parse_state("X"), ProcessState::Dead);
		assert_eq!(parse_state("x"), ProcessState::Dead);
	}

	#[test]
	fn test_parse_state_unknown() {
		assert_eq!(parse_state("Q"), ProcessState::Unknown);
	}

	#[test]
	fn test_parse_state_empty() {
		assert_eq!(parse_state(""), ProcessState::Unknown);
	}

	// parse_cmdline_content tests

	#[test]
	fn test_parse_cmdline_content_normal() {
		assert_eq!(
			parse_cmdline_content("/usr/bin/bash\0-l\0"),
			"/usr/bin/bash -l"
		);
	}

	#[test]
	fn test_parse_cmdline_content_empty() {
		assert_eq!(parse_cmdline_content(""), "");
	}

	// parse_proc_io tests

	#[test]
	fn test_parse_proc_io_normal() {
		let content = "\
			rchar: 100\n\
			wchar: 200\n\
			syscr: 10\n\
			syscw: 20\n\
			read_bytes: 4096\n\
			write_bytes: 8192\n\
			cancelled_write_bytes: 0\n";
		assert_eq!(parse_proc_io(content), (4096, 8192));
	}

	#[test]
	fn test_parse_proc_io_missing_fields() {
		assert_eq!(parse_proc_io("rchar: 100\nwchar: 200\n"), (0, 0));
	}

	#[test]
	fn test_parse_proc_io_non_numeric() {
		assert_eq!(
			parse_proc_io("read_bytes: abc\nwrite_bytes: def\n"),
			(0, 0)
		);
	}

	// rss_bytes_from_stat tests

	#[test]
	fn test_rss_bytes_from_stat_normal() {
		let page_size = nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE)
			.ok()
			.flatten()
			.unwrap_or(4096) as u64;
		let mut fields: Vec<String> = (0..52).map(|i| i.to_string()).collect();
		fields[23] = "100".to_string();
		assert_eq!(rss_bytes_from_stat(&fields), 100 * page_size);
	}

	#[test]
	fn test_rss_bytes_from_stat_short_vec() {
		let fields: Vec<String> = vec!["1".into(), "bash".into(), "S".into()];
		assert_eq!(rss_bytes_from_stat(&fields), 0);
	}

	#[test]
	fn test_rss_bytes_from_stat_non_numeric() {
		let mut fields: Vec<String> = (0..52).map(|i| i.to_string()).collect();
		fields[23] = "not_a_number".to_string();
		assert_eq!(rss_bytes_from_stat(&fields), 0);
	}
}
