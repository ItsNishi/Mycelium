//! Shared event types between eBPF kernel programs and userspace loader.
//!
//! All types are `#[repr(C)]` for stable ABI across the eBPF/userspace boundary.
//! This crate is `#![no_std]` so it can be used in eBPF programs.

#![no_std]

/// Maximum length of a task comm string (TASK_COMM_LEN in Linux).
pub const TASK_COMM_LEN: usize = 16;

/// Address family: IPv4 (AF_INET).
pub const AF_INET: u8 = 2;

/// Address family: IPv6 (AF_INET6).
pub const AF_INET6: u8 = 10;

/// Drop counter index: syscall ring buffer drops.
pub const DROP_COUNTER_SYSCALL: u32 = 0;

/// Drop counter index: network ring buffer drops.
pub const DROP_COUNTER_NET: u32 = 1;

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
///
/// Supports both IPv4 and IPv6. The `address_family` field discriminates:
/// - `AF_INET` (2): IPv4, first 4 bytes of `src_addr`/`dst_addr` hold the address
/// - `AF_INET6` (10): IPv6, all 16 bytes of `src_addr`/`dst_addr` hold the address
///
/// # Tracepoint format
///
/// Source: `include/trace/events/sock.h` (`inet_sock_set_state`), stable since Linux 4.16.
/// Offsets from `/sys/kernel/debug/tracing/events/sock/inet_sock_set_state/format`:
///
/// ```text
/// offset  8: const void* skaddr   (8 bytes)
/// offset 16: int oldstate         (4 bytes)
/// offset 20: int newstate         (4 bytes)
/// offset 24: __u16 sport          (2 bytes)
/// offset 26: __u16 dport          (2 bytes)
/// offset 28: __u16 family         (2 bytes)
/// offset 30: __u16 protocol       (2 bytes)
/// offset 32: __u8 saddr[4]        (4 bytes, IPv4 source)
/// offset 36: __u8 daddr[4]        (4 bytes, IPv4 destination)
/// offset 40: __u8 saddr_v6[16]    (16 bytes, IPv6 source)
/// offset 56: __u8 daddr_v6[16]    (16 bytes, IPv6 destination)
/// ```
///
/// For IPv4: we read 4 bytes at offset 32/36 and zero-extend into `[u8; 16]`.
/// For IPv6: we read 16 bytes at offset 40/56 directly.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetEvent {
	/// Process ID.
	pub pid: u32,
	/// Address family: AF_INET (2) or AF_INET6 (10).
	pub address_family: u8,
	/// IP protocol number (6 = TCP, 17 = UDP).
	pub protocol: u8,
	/// TCP state before transition.
	pub old_state: u8,
	/// TCP state after transition.
	pub new_state: u8,
	/// Source port in host byte order.
	pub src_port: u16,
	/// Destination port in host byte order.
	pub dst_port: u16,
	/// Process command name.
	pub comm: [u8; TASK_COMM_LEN],
	/// Source address (IPv4: first 4 bytes, rest zeroed; IPv6: all 16 bytes).
	pub src_addr: [u8; 16],
	/// Destination address (IPv4: first 4 bytes, rest zeroed; IPv6: all 16 bytes).
	pub dst_addr: [u8; 16],
	/// Kernel timestamp in nanoseconds.
	pub timestamp_ns: u64,
}

// Compile-time size assertions to catch ABI drift.
const _: () = assert!(core::mem::size_of::<SyscallEvent>() == 40);
const _: () = assert!(core::mem::size_of::<NetEvent>() == 72);

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
