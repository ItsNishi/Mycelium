//! eBPF probe loader and event pipeline.
//!
//! Loads compiled eBPF bytecode via aya, attaches programs to kernel
//! tracepoints, and drains events from ring buffers into an mpsc channel
//! for consumption by `read_probe_events()`.

use std::collections::HashMap as StdHashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use aya::Ebpf;
use aya::include_bytes_aligned;
use aya::maps::{Array, HashMap, MapData, RingBuf};
use aya::programs::{RawTracePoint, TracePoint};

use mycelium_core::error::{MyceliumError, Result};
use mycelium_core::types::{ProbeConfig, ProbeEvent, ProbeHandle, ProbeInfo, ProbeType};

use mycelium_ebpf_common::{AF_INET, AF_INET6, NetEvent, SyscallEvent, tcp_state_name};

/// Channel capacity for probe events.
const EVENT_CHANNEL_CAPACITY: usize = 10_000;

/// Ring buffer poll interval.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// State for a single active probe.
struct ActiveProbe {
	probe_type: ProbeType,
	target: Option<String>,
	events_captured: Arc<AtomicU64>,
	events_dropped: Arc<AtomicU64>,
	events_rx: Mutex<mpsc::Receiver<ProbeEvent>>,
	shutdown: Arc<AtomicBool>,
	poll_thread: Option<JoinHandle<()>>,
}

/// Global probe manager state.
pub struct ProbeState {
	next_handle: AtomicU64,
	active: Mutex<StdHashMap<u64, ActiveProbe>>,
	/// Keeps Ebpf instances alive so programs remain attached.
	ebpf_instances: Mutex<StdHashMap<u64, Ebpf>>,
}

impl ProbeState {
	pub fn new() -> Self {
		Self {
			next_handle: AtomicU64::new(1),
			active: Mutex::new(StdHashMap::new()),
			ebpf_instances: Mutex::new(StdHashMap::new()),
		}
	}
}

/// Attach an eBPF probe based on the given configuration.
pub fn attach_probe(config: &ProbeConfig, state: &ProbeState) -> Result<ProbeHandle> {
	let handle_id = state.next_handle.fetch_add(1, Ordering::Relaxed);

	// Load the eBPF bytecode compiled at build time.
	let ebpf_bytes = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/mycelium-ebpf"));

	let mut ebpf = Ebpf::load(ebpf_bytes).map_err(|e| {
		MyceliumError::ProbeError(format!("failed to load eBPF bytecode: {e}"))
	})?;

	// Populate filter maps from config.
	populate_filters(&mut ebpf, config)?;

	let (tx, rx) = mpsc::sync_channel::<ProbeEvent>(EVENT_CHANNEL_CAPACITY);
	let shutdown = Arc::new(AtomicBool::new(false));
	let events_captured = Arc::new(AtomicU64::new(0));
	let events_dropped = Arc::new(AtomicU64::new(0));

	match config.probe_type {
		ProbeType::SyscallTrace => {
			attach_syscall_trace(
				&mut ebpf, &tx, &shutdown, &events_captured, &events_dropped,
			)?;
		}
		ProbeType::NetworkMonitor => {
			attach_net_monitor(
				&mut ebpf, &tx, &shutdown, &events_captured, &events_dropped,
			)?;
		}
	}

	// Store the Ebpf instance to keep programs attached.
	state
		.ebpf_instances
		.lock()
		.unwrap()
		.insert(handle_id, ebpf);

	let active = ActiveProbe {
		probe_type: config.probe_type,
		target: config.target.clone(),
		events_captured,
		events_dropped,
		events_rx: Mutex::new(rx),
		shutdown,
		poll_thread: None,
	};

	state.active.lock().unwrap().insert(handle_id, active);

	Ok(ProbeHandle(handle_id))
}

/// Detach a running probe and clean up resources.
pub fn detach_probe(handle: ProbeHandle, state: &ProbeState) -> Result<()> {
	let mut active_map = state.active.lock().unwrap();
	let mut probe = active_map
		.remove(&handle.0)
		.ok_or_else(|| MyceliumError::NotFound(format!("probe handle {}", handle.0)))?;

	// Signal the poll thread to stop.
	probe.shutdown.store(true, Ordering::Relaxed);

	// Join the poll thread if it exists.
	if let Some(thread) = probe.poll_thread.take() {
		let _ = thread.join();
	}

	// Drop the Ebpf instance, which detaches the programs.
	state.ebpf_instances.lock().unwrap().remove(&handle.0);

	Ok(())
}

/// List all active probes.
pub fn list_probes(state: &ProbeState) -> Result<Vec<ProbeInfo>> {
	let active_map = state.active.lock().unwrap();
	let ebpf_map = state.ebpf_instances.lock().unwrap();
	let mut infos = Vec::with_capacity(active_map.len());

	for (&handle_id, probe) in active_map.iter() {
		let userspace_drops = probe.events_dropped.load(Ordering::Relaxed);

		// Read kernel-side drop counters from the DROP_COUNTERS array map.
		let kernel_drops = ebpf_map.get(&handle_id).map_or(0u64, |ebpf| {
			read_kernel_drop_counter(ebpf, probe.probe_type)
		});

		infos.push(ProbeInfo {
			handle: ProbeHandle(handle_id),
			probe_type: probe.probe_type,
			target: probe.target.clone(),
			events_captured: probe.events_captured.load(Ordering::Relaxed),
			events_dropped: userspace_drops + kernel_drops,
		});
	}

	Ok(infos)
}

/// Read pending events from a probe's channel.
pub fn read_probe_events(handle: &ProbeHandle, state: &ProbeState) -> Result<Vec<ProbeEvent>> {
	let active_map = state.active.lock().unwrap();
	let probe = active_map
		.get(&handle.0)
		.ok_or_else(|| MyceliumError::NotFound(format!("probe handle {}", handle.0)))?;

	let rx = probe.events_rx.lock().unwrap();
	let mut events = Vec::new();

	// Drain all available events without blocking.
	while let Ok(event) = rx.try_recv() {
		events.push(event);
	}

	Ok(events)
}

// -- Internal attachment helpers --

fn attach_syscall_trace(
	ebpf: &mut Ebpf,
	tx: &SyncSender<ProbeEvent>,
	shutdown: &Arc<AtomicBool>,
	events_captured: &Arc<AtomicU64>,
	events_dropped: &Arc<AtomicU64>,
) -> Result<()> {
	let program: &mut RawTracePoint = ebpf
		.program_mut("syscall_trace")
		.ok_or_else(|| {
			MyceliumError::ProbeError("syscall_trace program not found in eBPF binary".into())
		})?
		.try_into()
		.map_err(|e| MyceliumError::ProbeError(format!("wrong program type: {e}")))?;

	program
		.load()
		.map_err(|e| MyceliumError::ProbeError(format!("failed to load program: {e}")))?;

	program
		.attach("sys_enter")
		.map_err(|e| MyceliumError::ProbeError(format!("failed to attach to sys_enter: {e}")))?;

	// Set up ring buffer polling on a background thread.
	let ring_buf = RingBuf::try_from(
		ebpf.map_mut("SYSCALL_EVENTS")
			.ok_or_else(|| MyceliumError::ProbeError("SYSCALL_EVENTS map not found".into()))?,
	)
	.map_err(|e| MyceliumError::ProbeError(format!("failed to create ring buffer: {e}")))?;

	let tx = tx.clone();
	let shutdown = Arc::clone(shutdown);
	let events_captured = Arc::clone(events_captured);
	let events_dropped = Arc::clone(events_dropped);

	thread::Builder::new()
		.name("mycelium-syscall-poll".into())
		.spawn(move || {
			poll_syscall_ring_buffer(ring_buf, tx, shutdown, events_captured, events_dropped);
		})
		.map_err(|e| MyceliumError::ProbeError(format!("failed to spawn poll thread: {e}")))?;

	Ok(())
}

fn attach_net_monitor(
	ebpf: &mut Ebpf,
	tx: &SyncSender<ProbeEvent>,
	shutdown: &Arc<AtomicBool>,
	events_captured: &Arc<AtomicU64>,
	events_dropped: &Arc<AtomicU64>,
) -> Result<()> {
	let program: &mut TracePoint = ebpf
		.program_mut("net_monitor")
		.ok_or_else(|| {
			MyceliumError::ProbeError("net_monitor program not found in eBPF binary".into())
		})?
		.try_into()
		.map_err(|e| MyceliumError::ProbeError(format!("wrong program type: {e}")))?;

	program
		.load()
		.map_err(|e| MyceliumError::ProbeError(format!("failed to load program: {e}")))?;

	program
		.attach("sock", "inet_sock_set_state")
		.map_err(|e| {
			MyceliumError::ProbeError(format!(
				"failed to attach to sock/inet_sock_set_state: {e}"
			))
		})?;

	let ring_buf = RingBuf::try_from(
		ebpf.map_mut("NET_EVENTS")
			.ok_or_else(|| MyceliumError::ProbeError("NET_EVENTS map not found".into()))?,
	)
	.map_err(|e| MyceliumError::ProbeError(format!("failed to create ring buffer: {e}")))?;

	let tx = tx.clone();
	let shutdown = Arc::clone(shutdown);
	let events_captured = Arc::clone(events_captured);
	let events_dropped = Arc::clone(events_dropped);

	thread::Builder::new()
		.name("mycelium-net-poll".into())
		.spawn(move || {
			poll_net_ring_buffer(ring_buf, tx, shutdown, events_captured, events_dropped);
		})
		.map_err(|e| MyceliumError::ProbeError(format!("failed to spawn poll thread: {e}")))?;

	Ok(())
}

/// Populate PID and syscall filter maps from the probe configuration.
fn populate_filters(ebpf: &mut Ebpf, config: &ProbeConfig) -> Result<()> {
	// Parse target as PID filter.
	if let Some(ref target) = config.target {
		if let Ok(pid) = target.parse::<u32>() {
			let mut pid_filter: HashMap<&mut MapData, u32, u8> = HashMap::try_from(
				ebpf.map_mut("PID_FILTER")
					.ok_or_else(|| {
						MyceliumError::ProbeError("PID_FILTER map not found".into())
					})?,
			)
			.map_err(|e| {
				MyceliumError::ProbeError(format!("failed to open PID_FILTER: {e}"))
			})?;

			pid_filter.insert(pid, 1, 0).map_err(|e| {
				MyceliumError::ProbeError(format!("failed to insert PID filter: {e}"))
			})?;
		}
	}

	// Parse filter string for syscall numbers/names.
	if config.probe_type == ProbeType::SyscallTrace {
		if let Some(ref filter) = config.filter {
			let mut syscall_filter: HashMap<&mut MapData, u64, u8> = HashMap::try_from(
				ebpf.map_mut("SYSCALL_FILTER")
					.ok_or_else(|| {
						MyceliumError::ProbeError("SYSCALL_FILTER map not found".into())
					})?,
			)
			.map_err(|e| {
				MyceliumError::ProbeError(format!("failed to open SYSCALL_FILTER: {e}"))
			})?;

			for item in filter.split(',') {
				let item = item.trim();
				let nr = if let Ok(n) = item.parse::<u64>() {
					n
				} else {
					syscall_name_to_nr(item).ok_or_else(|| {
						MyceliumError::ProbeError(format!("unknown syscall: {item}"))
					})?
				};
				syscall_filter.insert(nr, 1, 0).map_err(|e| {
					MyceliumError::ProbeError(format!(
						"failed to insert syscall filter: {e}"
					))
				})?;
			}
		}
	}

	Ok(())
}

// -- Ring buffer poll loops --

fn poll_syscall_ring_buffer(
	mut ring_buf: RingBuf<MapData>,
	tx: SyncSender<ProbeEvent>,
	shutdown: Arc<AtomicBool>,
	events_captured: Arc<AtomicU64>,
	events_dropped: Arc<AtomicU64>,
) {
	while !shutdown.load(Ordering::Relaxed) {
		while let Some(item) = ring_buf.next() {
			let data = item.as_ref();
			if data.len() < core::mem::size_of::<SyscallEvent>() {
				continue;
			}

			// Safety: SyscallEvent is #[repr(C)] and we verified the size.
			let event: SyscallEvent = unsafe {
				core::ptr::read_unaligned(data.as_ptr() as *const SyscallEvent)
			};

			let comm = comm_to_string(&event.comm);
			let syscall_name = syscall_nr_to_name(event.syscall_nr);

			let probe_event = ProbeEvent {
				timestamp: event.timestamp_ns,
				pid: event.pid,
				process_name: comm,
				event_type: "syscall".into(),
				details: format!(
					"syscall_nr={} ({}) tid={}",
					event.syscall_nr, syscall_name, event.tid,
				),
			};

			events_captured.fetch_add(1, Ordering::Relaxed);

			if tx.try_send(probe_event).is_err() {
				// Channel full or disconnected; drop event but keep draining
				// the ring buffer to avoid kernel-side backpressure.
				events_dropped.fetch_add(1, Ordering::Relaxed);
				continue;
			}
		}

		thread::sleep(POLL_INTERVAL);
	}
}

fn poll_net_ring_buffer(
	mut ring_buf: RingBuf<MapData>,
	tx: SyncSender<ProbeEvent>,
	shutdown: Arc<AtomicBool>,
	events_captured: Arc<AtomicU64>,
	events_dropped: Arc<AtomicU64>,
) {
	while !shutdown.load(Ordering::Relaxed) {
		while let Some(item) = ring_buf.next() {
			let data = item.as_ref();
			if data.len() < core::mem::size_of::<NetEvent>() {
				continue;
			}

			let event: NetEvent = unsafe {
				core::ptr::read_unaligned(data.as_ptr() as *const NetEvent)
			};

			let comm = comm_to_string(&event.comm);
			let src = format_addr(event.address_family, &event.src_addr);
			let dst = format_addr(event.address_family, &event.dst_addr);
			let old_state = tcp_state_name(event.old_state);
			let new_state = tcp_state_name(event.new_state);

			let proto = match event.protocol {
				6 => "TCP",
				17 => "UDP",
				_ => "UNKNOWN",
			};

			let probe_event = ProbeEvent {
				timestamp: event.timestamp_ns,
				pid: event.pid,
				process_name: comm,
				event_type: "tcp_state".into(),
				details: format!(
					"{proto} {src}:{} -> {dst}:{} {old_state}->{new_state}",
					event.src_port, event.dst_port,
				),
			};

			events_captured.fetch_add(1, Ordering::Relaxed);

			if tx.try_send(probe_event).is_err() {
				// Channel full or disconnected; drop event but keep draining
				// the ring buffer to avoid kernel-side backpressure.
				events_dropped.fetch_add(1, Ordering::Relaxed);
				continue;
			}
		}

		thread::sleep(POLL_INTERVAL);
	}
}

// -- Helpers --

/// Format an address based on its address family.
///
/// - AF_INET: reads the first 4 bytes as an IPv4 address
/// - AF_INET6: reads all 16 bytes as an IPv6 address
/// - Unknown: returns a hex dump
fn format_addr(family: u8, addr: &[u8; 16]) -> String {
	match family {
		AF_INET => {
			let bytes: [u8; 4] = [addr[0], addr[1], addr[2], addr[3]];
			Ipv4Addr::from(bytes).to_string()
		}
		AF_INET6 => {
			Ipv6Addr::from(*addr).to_string()
		}
		_ => {
			format!("?{:02x?}", addr)
		}
	}
}

/// Read the kernel-side drop counter for the given probe type from the
/// DROP_COUNTERS array map. Returns 0 if the map is missing or unreadable.
fn read_kernel_drop_counter(ebpf: &Ebpf, probe_type: ProbeType) -> u64 {
	let index: u32 = match probe_type {
		ProbeType::SyscallTrace => mycelium_ebpf_common::DROP_COUNTER_SYSCALL,
		ProbeType::NetworkMonitor => mycelium_ebpf_common::DROP_COUNTER_NET,
	};

	let Some(map) = ebpf.map("DROP_COUNTERS") else {
		return 0;
	};

	let Ok(array) = Array::<&MapData, u64>::try_from(map) else {
		return 0;
	};

	array.get(&index, 0).unwrap_or(0)
}

/// Convert a kernel comm byte array to a String, trimming at the first null byte.
fn comm_to_string(comm: &[u8; 16]) -> String {
	let end = comm.iter().position(|&b| b == 0).unwrap_or(16);
	String::from_utf8_lossy(&comm[..end]).into_owned()
}

/// Look up a syscall number by name (x86_64).
fn syscall_name_to_nr(name: &str) -> Option<u64> {
	SYSCALL_TABLE.iter().find(|&&(_, n)| n == name).map(|&(nr, _)| nr)
}

/// Look up a syscall name by number (x86_64).
fn syscall_nr_to_name(nr: u64) -> &'static str {
	SYSCALL_TABLE
		.iter()
		.find(|&&(n, _)| n == nr)
		.map(|&(_, name)| name)
		.unwrap_or("unknown")
}

/// x86_64 syscall number -> name table (common syscalls).
const SYSCALL_TABLE: &[(u64, &str)] = &[
	(0, "read"),
	(1, "write"),
	(2, "open"),
	(3, "close"),
	(4, "stat"),
	(5, "fstat"),
	(6, "lstat"),
	(7, "poll"),
	(8, "lseek"),
	(9, "mmap"),
	(10, "mprotect"),
	(11, "munmap"),
	(12, "brk"),
	(13, "rt_sigaction"),
	(14, "rt_sigprocmask"),
	(15, "rt_sigreturn"),
	(16, "ioctl"),
	(17, "pread64"),
	(18, "pwrite64"),
	(19, "readv"),
	(20, "writev"),
	(21, "access"),
	(22, "pipe"),
	(23, "select"),
	(24, "sched_yield"),
	(25, "mremap"),
	(26, "msync"),
	(27, "mincore"),
	(28, "madvise"),
	(29, "shmget"),
	(30, "shmat"),
	(31, "shmctl"),
	(32, "dup"),
	(33, "dup2"),
	(34, "pause"),
	(35, "nanosleep"),
	(36, "getitimer"),
	(37, "alarm"),
	(38, "setitimer"),
	(39, "getpid"),
	(40, "sendfile"),
	(41, "socket"),
	(42, "connect"),
	(43, "accept"),
	(44, "sendto"),
	(45, "recvfrom"),
	(46, "sendmsg"),
	(47, "recvmsg"),
	(48, "shutdown"),
	(49, "bind"),
	(50, "listen"),
	(51, "getsockname"),
	(52, "getpeername"),
	(53, "socketpair"),
	(54, "setsockopt"),
	(55, "getsockopt"),
	(56, "clone"),
	(57, "fork"),
	(58, "vfork"),
	(59, "execve"),
	(60, "exit"),
	(61, "wait4"),
	(62, "kill"),
	(63, "uname"),
	(64, "semget"),
	(65, "semop"),
	(66, "semctl"),
	(67, "shmdt"),
	(68, "msgget"),
	(69, "msgsnd"),
	(70, "msgrcv"),
	(71, "msgctl"),
	(72, "fcntl"),
	(73, "flock"),
	(74, "fsync"),
	(75, "fdatasync"),
	(76, "truncate"),
	(77, "ftruncate"),
	(78, "getdents"),
	(79, "getcwd"),
	(80, "chdir"),
	(81, "fchdir"),
	(82, "rename"),
	(83, "mkdir"),
	(84, "rmdir"),
	(85, "creat"),
	(86, "link"),
	(87, "unlink"),
	(88, "symlink"),
	(89, "readlink"),
	(90, "chmod"),
	(91, "fchmod"),
	(92, "chown"),
	(93, "fchown"),
	(94, "lchown"),
	(95, "umask"),
	(96, "gettimeofday"),
	(97, "getrlimit"),
	(98, "getrusage"),
	(99, "sysinfo"),
	(100, "times"),
	(101, "ptrace"),
	(102, "getuid"),
	(103, "syslog"),
	(104, "getgid"),
	(105, "setuid"),
	(106, "setgid"),
	(107, "geteuid"),
	(108, "getegid"),
	(109, "setpgid"),
	(110, "getppid"),
	(111, "getpgrp"),
	(112, "setsid"),
	(113, "setreuid"),
	(114, "setregid"),
	(115, "getgroups"),
	(116, "setgroups"),
	(117, "setresuid"),
	(118, "getresuid"),
	(119, "setresgid"),
	(120, "getresgid"),
	(121, "getpgid"),
	(122, "setfsuid"),
	(123, "setfsgid"),
	(124, "getsid"),
	(125, "capget"),
	(126, "capset"),
	(127, "rt_sigpending"),
	(128, "rt_sigtimedwait"),
	(129, "rt_sigqueueinfo"),
	(130, "rt_sigsuspend"),
	(131, "sigaltstack"),
	(132, "utime"),
	(133, "mknod"),
	(134, "uselib"),
	(135, "personality"),
	(136, "ustat"),
	(137, "statfs"),
	(138, "fstatfs"),
	(139, "sysfs"),
	(140, "getpriority"),
	(141, "setpriority"),
	(142, "sched_setparam"),
	(143, "sched_getparam"),
	(144, "sched_setscheduler"),
	(145, "sched_getscheduler"),
	(146, "sched_get_priority_max"),
	(147, "sched_get_priority_min"),
	(148, "sched_rr_get_interval"),
	(149, "mlock"),
	(150, "munlock"),
	(151, "mlockall"),
	(152, "munlockall"),
	(153, "vhangup"),
	(154, "modify_ldt"),
	(155, "pivot_root"),
	(157, "prctl"),
	(158, "arch_prctl"),
	(159, "adjtimex"),
	(160, "setrlimit"),
	(161, "chroot"),
	(162, "sync"),
	(163, "acct"),
	(164, "settimeofday"),
	(165, "mount"),
	(166, "umount2"),
	(167, "swapon"),
	(168, "swapoff"),
	(169, "reboot"),
	(170, "sethostname"),
	(171, "setdomainname"),
	(175, "init_module"),
	(176, "delete_module"),
	(186, "gettid"),
	(187, "readahead"),
	(188, "setxattr"),
	(189, "lsetxattr"),
	(190, "fsetxattr"),
	(191, "getxattr"),
	(192, "lgetxattr"),
	(193, "fgetxattr"),
	(194, "listxattr"),
	(195, "llistxattr"),
	(196, "flistxattr"),
	(197, "removexattr"),
	(198, "lremovexattr"),
	(199, "fremovexattr"),
	(200, "tkill"),
	(201, "time"),
	(202, "futex"),
	(203, "sched_setaffinity"),
	(204, "sched_getaffinity"),
	(217, "getdents64"),
	(218, "set_tid_address"),
	(228, "clock_gettime"),
	(229, "clock_getres"),
	(230, "clock_nanosleep"),
	(231, "exit_group"),
	(232, "epoll_wait"),
	(233, "epoll_ctl"),
	(234, "tgkill"),
	(235, "utimes"),
	(257, "openat"),
	(258, "mkdirat"),
	(259, "mknodat"),
	(260, "fchownat"),
	(261, "futimesat"),
	(262, "newfstatat"),
	(263, "unlinkat"),
	(264, "renameat"),
	(265, "linkat"),
	(266, "symlinkat"),
	(267, "readlinkat"),
	(268, "fchmodat"),
	(269, "faccessat"),
	(270, "pselect6"),
	(271, "ppoll"),
	(272, "unshare"),
	(273, "set_robust_list"),
	(274, "get_robust_list"),
	(275, "splice"),
	(276, "tee"),
	(277, "sync_file_range"),
	(278, "vmsplice"),
	(279, "move_pages"),
	(280, "utimensat"),
	(281, "epoll_pwait"),
	(282, "signalfd"),
	(283, "timerfd_create"),
	(284, "eventfd"),
	(285, "fallocate"),
	(286, "timerfd_settime"),
	(287, "timerfd_gettime"),
	(288, "accept4"),
	(289, "signalfd4"),
	(290, "eventfd2"),
	(291, "epoll_create1"),
	(292, "dup3"),
	(293, "pipe2"),
	(294, "inotify_init1"),
	(295, "preadv"),
	(296, "pwritev"),
	(297, "rt_tgsigqueueinfo"),
	(298, "perf_event_open"),
	(299, "recvmmsg"),
	(302, "prlimit64"),
	(303, "name_to_handle_at"),
	(304, "open_by_handle_at"),
	(305, "clock_adjtime"),
	(306, "syncfs"),
	(307, "sendmmsg"),
	(308, "setns"),
	(309, "getcpu"),
	(310, "process_vm_readv"),
	(311, "process_vm_writev"),
	(312, "kcmp"),
	(313, "finit_module"),
	(314, "sched_setattr"),
	(315, "sched_getattr"),
	(316, "renameat2"),
	(317, "seccomp"),
	(318, "getrandom"),
	(319, "memfd_create"),
	(320, "kexec_file_load"),
	(321, "bpf"),
	(322, "execveat"),
	(323, "userfaultfd"),
	(324, "membarrier"),
	(325, "mlock2"),
	(326, "copy_file_range"),
	(327, "preadv2"),
	(328, "pwritev2"),
	(329, "pkey_mprotect"),
	(330, "pkey_alloc"),
	(331, "pkey_free"),
	(332, "statx"),
	(333, "io_pgetevents"),
	(334, "rseq"),
	(424, "pidfd_send_signal"),
	(425, "io_uring_setup"),
	(426, "io_uring_enter"),
	(427, "io_uring_register"),
	(428, "open_tree"),
	(429, "move_mount"),
	(430, "fsopen"),
	(431, "fsconfig"),
	(432, "fsmount"),
	(433, "fspick"),
	(434, "pidfd_open"),
	(435, "clone3"),
	(436, "close_range"),
	(437, "openat2"),
	(438, "pidfd_getfd"),
	(439, "faccessat2"),
	(440, "process_madvise"),
	(441, "epoll_pwait2"),
	(442, "mount_setattr"),
	(443, "quotactl_fd"),
	(444, "landlock_create_ruleset"),
	(445, "landlock_add_rule"),
	(446, "landlock_restrict_self"),
	(447, "memfd_secret"),
	(448, "process_mrelease"),
	(449, "futex_waitv"),
	(450, "set_mempolicy_home_node"),
	(451, "cachestat"),
	(452, "fchmodat2"),
];

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_comm_to_string_normal() {
		let mut comm = [0u8; 16];
		comm[..4].copy_from_slice(b"bash");
		assert_eq!(comm_to_string(&comm), "bash");
	}

	#[test]
	fn test_comm_to_string_full() {
		let comm = *b"0123456789abcdef";
		assert_eq!(comm_to_string(&comm), "0123456789abcdef");
	}

	#[test]
	fn test_syscall_nr_to_name() {
		assert_eq!(syscall_nr_to_name(59), "execve");
		assert_eq!(syscall_nr_to_name(257), "openat");
		assert_eq!(syscall_nr_to_name(0), "read");
		assert_eq!(syscall_nr_to_name(99999), "unknown");
	}

	#[test]
	fn test_syscall_name_to_nr() {
		assert_eq!(syscall_name_to_nr("execve"), Some(59));
		assert_eq!(syscall_name_to_nr("openat"), Some(257));
		assert_eq!(syscall_name_to_nr("nonexistent"), None);
	}

	#[test]
	fn test_format_addr_ipv4() {
		let mut addr = [0u8; 16];
		addr[0] = 192;
		addr[1] = 168;
		addr[2] = 1;
		addr[3] = 1;
		assert_eq!(format_addr(AF_INET, &addr), "192.168.1.1");
	}

	#[test]
	fn test_format_addr_ipv4_loopback() {
		let mut addr = [0u8; 16];
		addr[0] = 127;
		addr[3] = 1;
		assert_eq!(format_addr(AF_INET, &addr), "127.0.0.1");
	}

	#[test]
	fn test_format_addr_ipv6_loopback() {
		let mut addr = [0u8; 16];
		addr[15] = 1;
		assert_eq!(format_addr(AF_INET6, &addr), "::1");
	}

	#[test]
	fn test_format_addr_ipv6_full() {
		let addr: [u8; 16] = [
			0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		];
		assert_eq!(format_addr(AF_INET6, &addr), "2001:db8::1");
	}

	#[test]
	fn test_format_addr_unknown_family() {
		let addr = [0xffu8; 16];
		let result = format_addr(99, &addr);
		assert!(result.starts_with('?'));
	}
}
