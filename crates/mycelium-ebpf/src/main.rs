//! Mycelium eBPF programs: syscall tracing and network state monitoring.
//!
//! Compiled to `bpfel-unknown-none` target. Loaded at runtime by the
//! mycelium-linux crate's probe module via aya.

#![no_std]
#![no_main]

use aya_ebpf::{
	helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns},
	macros::{map, raw_tracepoint, tracepoint},
	maps::{Array, HashMap, RingBuf},
	programs::{RawTracePointContext, TracePointContext},
};
use mycelium_ebpf_common::{
	AF_INET, AF_INET6, DROP_COUNTER_NET, DROP_COUNTER_SYSCALL,
	NetEvent, SyscallEvent, TASK_COMM_LEN,
};

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

/// Kernel-side drop counters: index 0 = syscall drops, index 1 = net drops.
/// Incremented when a ring buffer reserve() fails (buffer full).
#[map]
static DROP_COUNTERS: Array<u64> = Array::with_max_entries(2, 0);

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
	} else {
		increment_drop_counter(DROP_COUNTER_SYSCALL);
	}

	Ok(0)
}

// -- Network monitoring --

/// Attaches to tracepoint/sock/inet_sock_set_state.
///
/// See `mycelium_ebpf_common::NetEvent` for full tracepoint format documentation.
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

	let mut src_addr = [0u8; 16];
	let mut dst_addr = [0u8; 16];
	let address_family: u8;

	match family {
		x if x == AF_INET as u16 => {
			// IPv4: read 4 bytes at offsets 32/36, zero-extend into [u8; 16].
			let saddr: [u8; 4] = unsafe { ctx.read_at(32) }.map_err(|_| 1i32)?;
			let daddr: [u8; 4] = unsafe { ctx.read_at(36) }.map_err(|_| 1i32)?;
			src_addr[..4].copy_from_slice(&saddr);
			dst_addr[..4].copy_from_slice(&daddr);
			address_family = AF_INET;
		}
		x if x == AF_INET6 as u16 => {
			// IPv6: read 16 bytes at offsets 40/56.
			src_addr = unsafe { ctx.read_at(40) }.map_err(|_| 1i32)?;
			dst_addr = unsafe { ctx.read_at(56) }.map_err(|_| 1i32)?;
			address_family = AF_INET6;
		}
		_ => {
			// Unknown address family, skip.
			return Ok(0);
		}
	}

	let timestamp_ns = bpf_ktime_get_ns();

	let event = NetEvent {
		pid,
		address_family,
		protocol: protocol as u8,
		old_state: oldstate as u8,
		new_state: newstate as u8,
		src_port: sport,
		dst_port: dport,
		comm,
		src_addr,
		dst_addr,
		timestamp_ns,
	};

	if let Some(mut entry) = NET_EVENTS.reserve::<NetEvent>(0) {
		unsafe {
			entry.as_mut_ptr().write(event);
		}
		entry.submit(0);
	} else {
		increment_drop_counter(DROP_COUNTER_NET);
	}

	Ok(0)
}

// -- Helpers --

/// Increment a drop counter by index (0=syscall, 1=net).
fn increment_drop_counter(index: u32) {
	if let Some(counter) = unsafe { DROP_COUNTERS.get_ptr_mut(index) } {
		unsafe {
			*counter += 1;
		}
	}
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
	loop {}
}
