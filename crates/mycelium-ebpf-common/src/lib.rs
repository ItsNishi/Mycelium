//! Shared event types between eBPF kernel programs and userspace loader.
//!
//! All types are `#[repr(C)]` for stable ABI across the eBPF/userspace boundary.
//! This crate is `#![no_std]` so it can be used in eBPF programs.

#![no_std]

/// Maximum length of a task comm string (TASK_COMM_LEN in Linux).
pub const TASK_COMM_LEN: usize = 16;

/// Event emitted by the syscall tracepoint program.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SyscallEvent {
	/// Process ID.
	pub pid: u32,
	/// Thread ID.
	pub tid: u32,
	/// Syscall number (x86_64 NR).
	pub syscall_nr: u64,
	/// Process command name.
	pub comm: [u8; TASK_COMM_LEN],
	/// Kernel timestamp in nanoseconds (ktime_get_ns).
	pub timestamp_ns: u64,
}

/// Event emitted by the network state-change tracepoint program.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetEvent {
	/// Process ID.
	pub pid: u32,
	/// Process command name.
	pub comm: [u8; TASK_COMM_LEN],
	/// Source IPv4 address in network byte order.
	pub src_addr: u32,
	/// Destination IPv4 address in network byte order.
	pub dst_addr: u32,
	/// Source port in host byte order.
	pub src_port: u16,
	/// Destination port in host byte order.
	pub dst_port: u16,
	/// IP protocol number (6 = TCP, 17 = UDP).
	pub protocol: u8,
	/// TCP state before transition.
	pub old_state: u8,
	/// TCP state after transition.
	pub new_state: u8,
	/// Padding for alignment.
	pub _pad: u8,
	/// Kernel timestamp in nanoseconds.
	pub timestamp_ns: u64,
}

/// IP protocol constants.
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

/// TCP state constants matching the kernel's enum.
pub const TCP_ESTABLISHED: u8 = 1;
pub const TCP_SYN_SENT: u8 = 2;
pub const TCP_SYN_RECV: u8 = 3;
pub const TCP_FIN_WAIT1: u8 = 4;
pub const TCP_FIN_WAIT2: u8 = 5;
pub const TCP_TIME_WAIT: u8 = 6;
pub const TCP_CLOSE: u8 = 7;
pub const TCP_CLOSE_WAIT: u8 = 8;
pub const TCP_LAST_ACK: u8 = 9;
pub const TCP_LISTEN: u8 = 10;
pub const TCP_CLOSING: u8 = 11;
pub const TCP_NEW_SYN_RECV: u8 = 12;

/// Convert a TCP state number to its name.
#[cfg(feature = "user")]
pub fn tcp_state_name(state: u8) -> &'static str {
	match state {
		TCP_ESTABLISHED => "ESTABLISHED",
		TCP_SYN_SENT => "SYN_SENT",
		TCP_SYN_RECV => "SYN_RECV",
		TCP_FIN_WAIT1 => "FIN_WAIT1",
		TCP_FIN_WAIT2 => "FIN_WAIT2",
		TCP_TIME_WAIT => "TIME_WAIT",
		TCP_CLOSE => "CLOSE",
		TCP_CLOSE_WAIT => "CLOSE_WAIT",
		TCP_LAST_ACK => "LAST_ACK",
		TCP_LISTEN => "LISTEN",
		TCP_CLOSING => "CLOSING",
		TCP_NEW_SYN_RECV => "NEW_SYN_RECV",
		_ => "UNKNOWN",
	}
}
