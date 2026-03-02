//! Mycelium eBPF programs: syscall tracing and network state monitoring.
//!
//! Compiled to `bpfel-unknown-none` target. Loaded at runtime by the
//! mycelium-linux crate's probe module via aya.

#![no_std]
#![no_main]

use aya_ebpf::{
	helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns},
	macros::{map, raw_tracepoint, tracepoint},
	maps::{HashMap, RingBuf},
	programs::{RawTracePointContext, TracePointContext},
};
use mycelium_ebpf_common::{NetEvent, SyscallEvent, TASK_COMM_LEN};

// -- Shared maps --

/// Ring buffer for syscall events (256 KiB).
#[map]
static SYSCALL_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Ring buffer for network events (256 KiB).
#[map]
static NET_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// PID filter: if non-empty, only trace PIDs present in this map.
#[map]
static PID_FILTER: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

/// Syscall number filter: if non-empty, only trace listed syscall numbers.
#[map]
static SYSCALL_FILTER: HashMap<u64, u8> = HashMap::with_max_entries(512, 0);

// -- Syscall tracing --

/// Attaches to raw_tracepoint/sys_enter.
///
/// For raw_tracepoint sys_enter:
///   arg(0) = struct pt_regs*
///   arg(1) = syscall number (long)
#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn syscall_trace(ctx: RawTracePointContext) -> i32 {
	match unsafe { try_syscall_trace(ctx) } {
		Ok(ret) => ret,
		Err(ret) => ret,
	}
}

unsafe fn try_syscall_trace(ctx: RawTracePointContext) -> Result<i32, i32> {
	let pid_tgid = bpf_get_current_pid_tgid();
	let pid = (pid_tgid >> 32) as u32;
	let tid = pid_tgid as u32;

	// Check PID filter: if the map has entries, skip PIDs not in it.
	// We use get_ptr to check existence without dereferencing.
	if unsafe { PID_FILTER.get(&0u32) }.is_some() || unsafe { PID_FILTER.get(&1u32) }.is_some() {
		// Map is potentially non-empty; check if this PID is in it.
		if unsafe { PID_FILTER.get(&pid) }.is_none() {
			return Ok(0);
		}
	}

	let syscall_nr: u64 = unsafe { ctx.arg::<u64>(1) };

	// Check syscall filter.
	if unsafe { SYSCALL_FILTER.get(&0u64) }.is_some()
		|| unsafe { SYSCALL_FILTER.get(&1u64) }.is_some()
	{
		if unsafe { SYSCALL_FILTER.get(&syscall_nr) }.is_none() {
			return Ok(0);
		}
	}

	let comm = bpf_get_current_comm().map_err(|_| 1i32)?;
	let timestamp_ns = bpf_ktime_get_ns();

	let event = SyscallEvent {
		pid,
		tid,
		syscall_nr,
		comm,
		timestamp_ns,
	};

	if let Some(mut entry) = SYSCALL_EVENTS.reserve::<SyscallEvent>(0) {
		unsafe {
			entry.as_mut_ptr().write(event);
		}
		entry.submit(0);
	}

	Ok(0)
}

// -- Network monitoring --

/// Attaches to tracepoint/sock/inet_sock_set_state.
///
/// Tracepoint format offsets (from /sys/kernel/debug/tracing/events/sock/inet_sock_set_state/format):
///   offset  8: const void* skaddr   (8 bytes)
///   offset 16: int oldstate         (4 bytes)
///   offset 20: int newstate         (4 bytes)
///   offset 24: __u16 sport          (2 bytes)
///   offset 26: __u16 dport          (2 bytes)
///   offset 28: __u16 family         (2 bytes)
///   offset 30: __u16 protocol       (2 bytes)
///   offset 32: __u8 saddr[4]        (4 bytes, IPv4)
///   offset 36: __u8 daddr[4]        (4 bytes, IPv4)
#[tracepoint(category = "sock", name = "inet_sock_set_state")]
pub fn net_monitor(ctx: TracePointContext) -> i32 {
	match unsafe { try_net_monitor(ctx) } {
		Ok(ret) => ret,
		Err(ret) => ret,
	}
}

unsafe fn try_net_monitor(ctx: TracePointContext) -> Result<i32, i32> {
	let pid_tgid = bpf_get_current_pid_tgid();
	let pid = (pid_tgid >> 32) as u32;

	// Check PID filter.
	if unsafe { PID_FILTER.get(&0u32) }.is_some() || unsafe { PID_FILTER.get(&1u32) }.is_some() {
		if unsafe { PID_FILTER.get(&pid) }.is_none() {
			return Ok(0);
		}
	}

	let comm = bpf_get_current_comm().map_err(|_| 1i32)?;

	// Read tracepoint fields at known offsets.
	let oldstate: i32 = unsafe { ctx.read_at(16) }.map_err(|_| 1i32)?;
	let newstate: i32 = unsafe { ctx.read_at(20) }.map_err(|_| 1i32)?;
	let sport: u16 = unsafe { ctx.read_at(24) }.map_err(|_| 1i32)?;
	let dport: u16 = unsafe { ctx.read_at(26) }.map_err(|_| 1i32)?;
	let family: u16 = unsafe { ctx.read_at(28) }.map_err(|_| 1i32)?;
	let protocol: u16 = unsafe { ctx.read_at(30) }.map_err(|_| 1i32)?;

	// Only handle AF_INET (IPv4) for now.
	const AF_INET: u16 = 2;
	if family != AF_INET {
		return Ok(0);
	}

	let src_addr: u32 = unsafe { ctx.read_at(32) }.map_err(|_| 1i32)?;
	let dst_addr: u32 = unsafe { ctx.read_at(36) }.map_err(|_| 1i32)?;

	let timestamp_ns = bpf_ktime_get_ns();

	let event = NetEvent {
		pid,
		comm,
		src_addr,
		dst_addr,
		src_port: sport,
		dst_port: dport,
		protocol: protocol as u8,
		old_state: oldstate as u8,
		new_state: newstate as u8,
		_pad: 0,
		timestamp_ns,
	};

	if let Some(mut entry) = NET_EVENTS.reserve::<NetEvent>(0) {
		unsafe {
			entry.as_mut_ptr().write(event);
		}
		entry.submit(0);
	}

	Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
	loop {}
}
