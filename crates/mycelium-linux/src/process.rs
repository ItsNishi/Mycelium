//! Process queries and control via /proc and signals.

use mycelium_core::error::{MyceliumError, Result};
use mycelium_core::types::{
	HandleInfo, PrivilegeInfo, ProcessInfo, ProcessModule, ProcessResource,
	ProcessState, Signal, ThreadInfo, TokenGroup, TokenInfo,
};
use std::collections::HashMap;
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

pub fn process_environment(pid: u32) -> Result<Vec<(String, String)>> {
	let path = format!("/proc/{pid}/environ");
	let content = fs::read(&path).map_err(|e| {
		if e.kind() == std::io::ErrorKind::NotFound {
			MyceliumError::NotFound(format!("process {pid}"))
		} else if e.kind() == std::io::ErrorKind::PermissionDenied {
			MyceliumError::PermissionDenied(format!("cannot read {path}"))
		} else {
			MyceliumError::IoError(e)
		}
	})?;

	let text = String::from_utf8_lossy(&content);
	let vars: Vec<(String, String)> = text
		.split('\0')
		.filter(|s| !s.is_empty())
		.filter_map(|entry| {
			entry.split_once('=').map(|(k, v)| (k.to_string(), v.to_string()))
		})
		.collect();

	Ok(vars)
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

// ---- Linux capabilities table ----
// CAP_CHOWN (0) through CAP_CHECKPOINT_RESTORE (40)

const CAPABILITY_NAMES: &[&str] = &[
	"CAP_CHOWN",                  // 0
	"CAP_DAC_OVERRIDE",           // 1
	"CAP_DAC_READ_SEARCH",        // 2
	"CAP_FOWNER",                 // 3
	"CAP_FSETID",                 // 4
	"CAP_KILL",                   // 5
	"CAP_SETGID",                 // 6
	"CAP_SETUID",                 // 7
	"CAP_SETPCAP",                // 8
	"CAP_LINUX_IMMUTABLE",        // 9
	"CAP_NET_BIND_SERVICE",       // 10
	"CAP_NET_BROADCAST",          // 11
	"CAP_NET_ADMIN",              // 12
	"CAP_NET_RAW",                // 13
	"CAP_IPC_LOCK",               // 14
	"CAP_IPC_OWNER",              // 15
	"CAP_SYS_MODULE",             // 16
	"CAP_SYS_RAWIO",              // 17
	"CAP_SYS_CHROOT",             // 18
	"CAP_SYS_PTRACE",             // 19
	"CAP_SYS_PACCT",              // 20
	"CAP_SYS_ADMIN",              // 21
	"CAP_SYS_BOOT",               // 22
	"CAP_SYS_NICE",               // 23
	"CAP_SYS_RESOURCE",           // 24
	"CAP_SYS_TIME",               // 25
	"CAP_SYS_TTY_CONFIG",         // 26
	"CAP_MKNOD",                  // 27
	"CAP_LEASE",                  // 28
	"CAP_AUDIT_WRITE",            // 29
	"CAP_AUDIT_CONTROL",          // 30
	"CAP_SETFCAP",                // 31
	"CAP_MAC_OVERRIDE",           // 32
	"CAP_MAC_ADMIN",              // 33
	"CAP_SYSLOG",                 // 34
	"CAP_WAKE_ALARM",             // 35
	"CAP_BLOCK_SUSPEND",          // 36
	"CAP_AUDIT_READ",             // 37
	"CAP_PERFMON",                // 38
	"CAP_BPF",                    // 39
	"CAP_CHECKPOINT_RESTORE",     // 40
];

/// Decode a capability hex bitmask into a set of bit indices.
fn decode_caps(hex: &str) -> u64 {
	u64::from_str_radix(hex.trim(), 16).unwrap_or(0)
}

/// Parse capabilities from /proc/[pid]/status content.
/// Returns (permitted_bitmask, effective_bitmask).
fn parse_capabilities(content: &str) -> (u64, u64) {
	let mut permitted = 0u64;
	let mut effective = 0u64;
	for line in content.lines() {
		if let Some(hex) = line.strip_prefix("CapPrm:") {
			permitted = decode_caps(hex);
		} else if let Some(hex) = line.strip_prefix("CapEff:") {
			effective = decode_caps(hex);
		}
	}
	(permitted, effective)
}

/// Build a list of PrivilegeInfo from capability bitmasks.
fn capabilities_to_privileges(permitted: u64, effective: u64) -> Vec<PrivilegeInfo> {
	let mut privs = Vec::new();
	for (i, name) in CAPABILITY_NAMES.iter().enumerate() {
		if permitted & (1u64 << i) != 0 {
			privs.push(PrivilegeInfo {
				name: name.to_string(),
				enabled: effective & (1u64 << i) != 0,
			});
		}
	}
	privs
}

// ---- Thread listing ----

const MAX_THREADS: usize = 10_000;

/// Parse a /proc/[pid]/task/[tid]/stat file to extract the thread priority.
fn parse_thread_priority(content: &str, tid: u32) -> i32 {
	// Field 17 (0-indexed) is the priority
	parse_stat_content(content, tid)
		.ok()
		.and_then(|fields| fields.get(17).and_then(|v| v.parse().ok()))
		.unwrap_or(0)
}

pub fn list_process_threads(pid: u32) -> Result<Vec<ThreadInfo>> {
	let task_dir = format!("/proc/{pid}/task");
	if !Path::new(&task_dir).exists() {
		return Err(MyceliumError::NotFound(format!("process {pid}")));
	}

	let entries = fs::read_dir(&task_dir).map_err(|e| match e.kind() {
		std::io::ErrorKind::PermissionDenied => {
			MyceliumError::PermissionDenied(format!("cannot read {task_dir}"))
		}
		_ => MyceliumError::IoError(e),
	})?;

	let mut threads = Vec::new();
	for entry in entries {
		let entry = entry?;
		let Some(tid) = entry.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
			continue;
		};

		let stat_path = format!("/proc/{pid}/task/{tid}/stat");
		let priority = fs::read_to_string(&stat_path)
			.ok()
			.map(|c| parse_thread_priority(&c, tid))
			.unwrap_or(0);

		threads.push(ThreadInfo {
			tid,
			pid,
			priority,
		});

		if threads.len() >= MAX_THREADS {
			break;
		}
	}

	threads.sort_by_key(|t| t.tid);
	Ok(threads)
}

// ---- Module listing ----

pub fn list_process_modules(pid: u32) -> Result<Vec<ProcessModule>> {
	let regions = crate::memory::process_memory_maps(pid)?;

	// Get the main executable path
	let exe_path = fs::read_link(format!("/proc/{pid}/exe"))
		.ok()
		.map(|p| p.to_string_lossy().to_string());

	// Group contiguous regions by pathname, tracking min start and max end
	let mut module_map: HashMap<String, (u64, u64)> = HashMap::new();

	for region in &regions {
		let path = match &region.pathname {
			Some(p) if p.contains(".so") || exe_path.as_deref() == Some(p.as_str()) => p,
			_ => continue,
		};

		let entry = module_map
			.entry(path.clone())
			.or_insert((region.start_address, region.end_address));
		if region.start_address < entry.0 {
			entry.0 = region.start_address;
		}
		if region.end_address > entry.1 {
			entry.1 = region.end_address;
		}
	}

	let mut modules: Vec<ProcessModule> = module_map
		.into_iter()
		.map(|(path, (base, end))| {
			let name = path
				.rsplit('/')
				.next()
				.unwrap_or(&path)
				.to_string();
			ProcessModule {
				name,
				path,
				base_address: base,
				size: end - base,
			}
		})
		.collect();

	modules.sort_by_key(|m| m.base_address);
	Ok(modules)
}

// ---- Privilege listing ----

pub fn list_process_privileges(pid: u32) -> Result<Vec<PrivilegeInfo>> {
	let status_path = format!("/proc/{pid}/status");
	if !Path::new(&format!("/proc/{pid}")).exists() {
		return Err(MyceliumError::NotFound(format!("process {pid}")));
	}

	let content = fs::read_to_string(&status_path).map_err(|e| match e.kind() {
		std::io::ErrorKind::PermissionDenied => {
			MyceliumError::PermissionDenied(format!("cannot read {status_path}"))
		}
		_ => MyceliumError::IoError(e),
	})?;

	let (permitted, effective) = parse_capabilities(&content);
	Ok(capabilities_to_privileges(permitted, effective))
}

// ---- Handle / file descriptor listing ----

/// Classify an fd target path into an object type.
fn classify_fd_target(target: &str) -> &'static str {
	if target.starts_with("socket:") {
		"Socket"
	} else if target.starts_with("pipe:") {
		"Pipe"
	} else if target.starts_with("anon_inode:") {
		"AnonInode"
	} else if target.starts_with('/') {
		"File"
	} else {
		"Other"
	}
}

/// Parse the octal flags from /proc/[pid]/fdinfo/[fd].
fn parse_fdinfo_flags(content: &str) -> u32 {
	content
		.lines()
		.find(|l| l.starts_with("flags:"))
		.and_then(|l| l.split_whitespace().nth(1))
		.and_then(|v| u32::from_str_radix(v.trim(), 8).ok())
		.unwrap_or(0)
}

pub fn list_process_handles(pid: u32) -> Result<Vec<HandleInfo>> {
	let fd_dir = format!("/proc/{pid}/fd");
	if !Path::new(&format!("/proc/{pid}")).exists() {
		return Err(MyceliumError::NotFound(format!("process {pid}")));
	}

	let entries = fs::read_dir(&fd_dir).map_err(|e| match e.kind() {
		std::io::ErrorKind::PermissionDenied => {
			MyceliumError::PermissionDenied(format!("cannot read {fd_dir}"))
		}
		_ => MyceliumError::IoError(e),
	})?;

	let mut handles = Vec::new();
	for entry in entries {
		let entry = entry?;
		let fd_str = entry.file_name();
		let Some(fd_num) = fd_str.to_str().and_then(|s| s.parse::<u64>().ok()) else {
			continue;
		};

		let target = fs::read_link(entry.path())
			.ok()
			.map(|p| p.to_string_lossy().to_string())
			.unwrap_or_default();

		let object_type = classify_fd_target(&target).to_string();

		let flags_path = format!("/proc/{pid}/fdinfo/{fd_num}");
		let access_mask = fs::read_to_string(&flags_path)
			.ok()
			.map(|c| parse_fdinfo_flags(&c))
			.unwrap_or(0);

		handles.push(HandleInfo {
			handle_value: fd_num,
			object_type,
			name: if target.is_empty() {
				None
			} else {
				Some(target)
			},
			access_mask,
		});
	}

	handles.sort_by_key(|h| h.handle_value);
	Ok(handles)
}

// ---- Token inspection ----

/// Parse UIDs from /proc/[pid]/status. Returns (real, effective, saved, fs).
fn parse_status_ids(content: &str, prefix: &str) -> Vec<u32> {
	content
		.lines()
		.find(|l| l.starts_with(prefix))
		.map(|l| {
			l.split_whitespace()
				.skip(1)
				.filter_map(|v| v.parse().ok())
				.collect()
		})
		.unwrap_or_default()
}

/// Parse the Groups: line from /proc/[pid]/status.
fn parse_status_groups(content: &str) -> Vec<u32> {
	content
		.lines()
		.find(|l| l.starts_with("Groups:"))
		.map(|l| {
			l.split_whitespace()
				.skip(1)
				.filter_map(|v| v.parse().ok())
				.collect()
		})
		.unwrap_or_default()
}

/// Parse the Seccomp: field from /proc/[pid]/status.
fn parse_seccomp(content: &str) -> u32 {
	content
		.lines()
		.find(|l| l.starts_with("Seccomp:"))
		.and_then(|l| l.split_whitespace().nth(1))
		.and_then(|v| v.parse().ok())
		.unwrap_or(0)
}

fn groupname_for_gid(gid: u32) -> String {
	nix::unistd::Group::from_gid(nix::unistd::Gid::from_raw(gid))
		.ok()
		.flatten()
		.map(|g| g.name)
		.unwrap_or_else(|| gid.to_string())
}

pub fn inspect_process_token(pid: u32) -> Result<TokenInfo> {
	let status_path = format!("/proc/{pid}/status");
	if !Path::new(&format!("/proc/{pid}")).exists() {
		return Err(MyceliumError::NotFound(format!("process {pid}")));
	}

	let content = fs::read_to_string(&status_path).map_err(|e| match e.kind() {
		std::io::ErrorKind::PermissionDenied => {
			MyceliumError::PermissionDenied(format!("cannot read {status_path}"))
		}
		_ => MyceliumError::IoError(e),
	})?;

	let uids = parse_status_ids(&content, "Uid:");
	let gids = parse_status_ids(&content, "Gid:");
	let effective_uid = uids.get(1).copied().unwrap_or(0);
	let effective_gid = gids.get(1).copied().unwrap_or(0);

	let user = username_for_uid(effective_uid);

	// Integrity level mapping
	let integrity_level = if effective_uid == 0 {
		"System"
	} else if effective_uid < 1000 {
		"High"
	} else {
		"Medium"
	}
	.to_string();

	let is_elevated = effective_uid == 0;

	// Seccomp check for is_restricted
	let seccomp = parse_seccomp(&content);
	let is_restricted = seccomp == 2; // SECCOMP_MODE_FILTER

	// Session ID from /proc/[pid]/stat field 5
	let session_id = parse_stat(pid)
		.ok()
		.and_then(|fields| fields.get(5).and_then(|v| v.parse().ok()))
		.unwrap_or(0);

	// Groups
	let group_ids = parse_status_groups(&content);
	let groups: Vec<TokenGroup> = std::iter::once(effective_gid)
		.chain(group_ids)
		.collect::<Vec<_>>()
		.into_iter()
		.map(|gid| {
			let name = groupname_for_gid(gid);
			TokenGroup {
				name,
				sid: gid.to_string(),
				attributes: vec!["Enabled".to_string()],
			}
		})
		.collect();

	// Capabilities as privileges
	let (permitted, effective) = parse_capabilities(&content);
	let privileges = capabilities_to_privileges(permitted, effective);

	Ok(TokenInfo {
		pid,
		user,
		integrity_level,
		token_type: "Primary".to_string(),
		impersonation_level: None,
		elevation_type: if is_elevated {
			"Full".to_string()
		} else {
			"Limited".to_string()
		},
		is_elevated,
		is_restricted,
		session_id,
		groups,
		privileges,
	})
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

	// decode_caps tests

	#[test]
	fn test_decode_caps_zero() {
		assert_eq!(decode_caps("0000000000000000"), 0);
	}

	#[test]
	fn test_decode_caps_all_set() {
		assert_eq!(decode_caps("000001ffffffffff"), 0x1ffffffffff);
	}

	#[test]
	fn test_decode_caps_with_whitespace() {
		assert_eq!(decode_caps("  00000000a80425fb\n"), 0xa80425fb);
	}

	#[test]
	fn test_decode_caps_invalid() {
		assert_eq!(decode_caps("zzzz"), 0);
	}

	// parse_capabilities tests

	#[test]
	fn test_parse_capabilities_normal() {
		let content = "Name:\ttest\nCapPrm:\t000001ffffffffff\nCapEff:\t000001ffffffffff\n";
		let (prm, eff) = parse_capabilities(content);
		assert_eq!(prm, 0x1ffffffffff);
		assert_eq!(eff, 0x1ffffffffff);
	}

	#[test]
	fn test_parse_capabilities_partial() {
		let content = "Name:\ttest\nCapPrm:\t0000000000003c00\nCapEff:\t0000000000000400\n";
		let (prm, eff) = parse_capabilities(content);
		// CAP_NET_BIND_SERVICE(10), CAP_NET_BROADCAST(11), CAP_NET_ADMIN(12), CAP_NET_RAW(13)
		assert_eq!(prm, 0x3c00);
		// Only CAP_NET_BIND_SERVICE(10) effective
		assert_eq!(eff, 0x0400);
	}

	#[test]
	fn test_parse_capabilities_missing() {
		let content = "Name:\ttest\nUid:\t1000\t1000\t1000\t1000\n";
		let (prm, eff) = parse_capabilities(content);
		assert_eq!(prm, 0);
		assert_eq!(eff, 0);
	}

	// capabilities_to_privileges tests

	#[test]
	fn test_capabilities_to_privileges_root() {
		// All 41 caps permitted and effective
		let all = 0x1ffffffffff_u64;
		let privs = capabilities_to_privileges(all, all);
		assert_eq!(privs.len(), 41);
		assert!(privs.iter().all(|p| p.enabled));
		assert_eq!(privs[0].name, "CAP_CHOWN");
		assert_eq!(privs[40].name, "CAP_CHECKPOINT_RESTORE");
	}

	#[test]
	fn test_capabilities_to_privileges_none() {
		let privs = capabilities_to_privileges(0, 0);
		assert!(privs.is_empty());
	}

	#[test]
	fn test_capabilities_to_privileges_permitted_not_effective() {
		// CAP_NET_RAW (13) permitted but not effective
		let permitted = 1u64 << 13;
		let effective = 0u64;
		let privs = capabilities_to_privileges(permitted, effective);
		assert_eq!(privs.len(), 1);
		assert_eq!(privs[0].name, "CAP_NET_RAW");
		assert!(!privs[0].enabled);
	}

	// parse_thread_priority tests

	#[test]
	fn test_parse_thread_priority_normal() {
		// man proc(5) field 18 is priority (1-indexed) -> vector index 17 (0-indexed)
		// pid(0) comm(1) state(2) ppid(3) pgrp(4) session(5) tty(6) tpgid(7) flags(8)
		// minflt(9) cminflt(10) majflt(11) cmajflt(12) utime(13) stime(14) cutime(15)
		// cstime(16) priority(17)
		let content = "42 (bash) S 1 42 42 0 -1 4194560 0 0 0 0 10 5 0 0 20 0 1 0 100";
		assert_eq!(parse_thread_priority(content, 42), 20);
	}

	#[test]
	fn test_parse_thread_priority_negative() {
		let content = "42 (bash) S 1 42 42 0 -1 4194560 0 0 0 0 10 5 0 0 -5 0 1 0 100";
		assert_eq!(parse_thread_priority(content, 42), -5);
	}

	#[test]
	fn test_parse_thread_priority_malformed() {
		assert_eq!(parse_thread_priority("garbage", 42), 0);
	}

	// classify_fd_target tests

	#[test]
	fn test_classify_fd_target_socket() {
		assert_eq!(classify_fd_target("socket:[12345]"), "Socket");
	}

	#[test]
	fn test_classify_fd_target_pipe() {
		assert_eq!(classify_fd_target("pipe:[67890]"), "Pipe");
	}

	#[test]
	fn test_classify_fd_target_file() {
		assert_eq!(classify_fd_target("/usr/lib/libc.so.6"), "File");
	}

	#[test]
	fn test_classify_fd_target_anon_inode() {
		assert_eq!(classify_fd_target("anon_inode:[eventpoll]"), "AnonInode");
	}

	#[test]
	fn test_classify_fd_target_other() {
		assert_eq!(classify_fd_target("[vvar]"), "Other");
	}

	// parse_fdinfo_flags tests

	#[test]
	fn test_parse_fdinfo_flags_read_only() {
		// Octal 0100000 = O_LARGEFILE on many archs
		let content = "pos:\t0\nflags:\t0100000\nmnt_id:\t25\n";
		assert_eq!(parse_fdinfo_flags(content), 0o100000);
	}

	#[test]
	fn test_parse_fdinfo_flags_read_write() {
		let content = "pos:\t0\nflags:\t0100002\nmnt_id:\t25\n";
		assert_eq!(parse_fdinfo_flags(content), 0o100002);
	}

	#[test]
	fn test_parse_fdinfo_flags_missing() {
		let content = "pos:\t0\nmnt_id:\t25\n";
		assert_eq!(parse_fdinfo_flags(content), 0);
	}

	// parse_status_ids tests

	#[test]
	fn test_parse_status_ids_normal() {
		let content = "Uid:\t1000\t1000\t1000\t1000\nGid:\t100\t100\t100\t100\n";
		let uids = parse_status_ids(content, "Uid:");
		assert_eq!(uids, vec![1000, 1000, 1000, 1000]);
		let gids = parse_status_ids(content, "Gid:");
		assert_eq!(gids, vec![100, 100, 100, 100]);
	}

	#[test]
	fn test_parse_status_ids_root() {
		let content = "Uid:\t0\t0\t0\t0\n";
		let uids = parse_status_ids(content, "Uid:");
		assert_eq!(uids, vec![0, 0, 0, 0]);
	}

	#[test]
	fn test_parse_status_ids_missing() {
		let content = "Name:\ttest\n";
		let uids = parse_status_ids(content, "Uid:");
		assert!(uids.is_empty());
	}

	// parse_status_groups tests

	#[test]
	fn test_parse_status_groups_normal() {
		let content = "Groups:\t100 10 27 999\n";
		assert_eq!(parse_status_groups(content), vec![100, 10, 27, 999]);
	}

	#[test]
	fn test_parse_status_groups_empty() {
		let content = "Groups:\t\n";
		assert!(parse_status_groups(content).is_empty());
	}

	#[test]
	fn test_parse_status_groups_missing() {
		let content = "Name:\ttest\n";
		assert!(parse_status_groups(content).is_empty());
	}

	// parse_seccomp tests

	#[test]
	fn test_parse_seccomp_disabled() {
		let content = "Seccomp:\t0\n";
		assert_eq!(parse_seccomp(content), 0);
	}

	#[test]
	fn test_parse_seccomp_strict() {
		let content = "Seccomp:\t1\n";
		assert_eq!(parse_seccomp(content), 1);
	}

	#[test]
	fn test_parse_seccomp_filter() {
		let content = "Seccomp:\t2\n";
		assert_eq!(parse_seccomp(content), 2);
	}

	#[test]
	fn test_parse_seccomp_missing() {
		let content = "Name:\ttest\n";
		assert_eq!(parse_seccomp(content), 0);
	}
}
