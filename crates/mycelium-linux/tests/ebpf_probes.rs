//! eBPF probe integration tests.
//!
//! All tests are `#[ignore]` and require root + CAP_BPF.
//! Run with: `sudo -E cargo test --test ebpf_probes -p mycelium-linux --features ebpf -- --ignored`

#![cfg(feature = "ebpf")]

use std::net::TcpStream;
use std::thread;
use std::time::Duration;

use mycelium_core::platform::*;
use mycelium_core::types::*;
use mycelium_linux::LinuxPlatform;

fn platform() -> LinuxPlatform {
	LinuxPlatform::new()
}

fn own_pid() -> u32 {
	std::process::id()
}

#[test]
#[ignore]
fn syscall_probe_lifecycle() {
	let p = platform();
	let config = ProbeConfig {
		probe_type: ProbeType::SyscallTrace,
		target: Some(own_pid().to_string()),
		filter: None,
	};

	let handle = p.attach_probe(&config).unwrap();

	// Generate some syscalls.
	for _ in 0..10 {
		let _ = std::fs::metadata("/proc/self/status");
	}
	thread::sleep(Duration::from_millis(500));

	let events = p.read_probe_events(&handle).unwrap();
	assert!(!events.is_empty(), "should have captured syscall events");

	// Verify all events have our PID.
	for event in &events {
		assert_eq!(event.pid, own_pid(), "event PID should match our PID");
	}

	p.detach_probe(handle).unwrap();
}

#[test]
#[ignore]
fn net_probe_lifecycle() {
	let p = platform();
	let config = ProbeConfig {
		probe_type: ProbeType::NetworkMonitor,
		target: Some(own_pid().to_string()),
		filter: None,
	};

	let handle = p.attach_probe(&config).unwrap();

	// Generate a TCP connection to trigger inet_sock_set_state.
	let _ = TcpStream::connect("127.0.0.1:22")
		.or_else(|_| TcpStream::connect("127.0.0.1:80"))
		.or_else(|_| TcpStream::connect("127.0.0.1:443"));
	thread::sleep(Duration::from_millis(500));

	let events = p.read_probe_events(&handle).unwrap();
	// Events might be empty if no service is listening, but the call shouldn't error.
	for event in &events {
		assert_eq!(event.pid, own_pid());
		assert_eq!(event.event_type, "tcp_state");
	}

	p.detach_probe(handle).unwrap();
}

#[test]
#[ignore]
fn ipv6_net_event() {
	let p = platform();
	let config = ProbeConfig {
		probe_type: ProbeType::NetworkMonitor,
		target: Some(own_pid().to_string()),
		filter: None,
	};

	let handle = p.attach_probe(&config).unwrap();

	// Connect to IPv6 loopback. This may fail if nothing listens, but the
	// inet_sock_set_state tracepoint still fires on state transitions.
	let _ = TcpStream::connect("[::1]:22")
		.or_else(|_| TcpStream::connect("[::1]:80"));
	thread::sleep(Duration::from_millis(500));

	let events = p.read_probe_events(&handle).unwrap();

	// If we got events, verify IPv6 addresses appear.
	let has_v6 = events.iter().any(|e| e.details.contains("::"));
	if !events.is_empty() {
		assert!(has_v6, "IPv6 connection should produce event with '::' address");
	}

	p.detach_probe(handle).unwrap();
}

#[test]
#[ignore]
fn list_probes_while_attached() {
	let p = platform();

	let config1 = ProbeConfig {
		probe_type: ProbeType::SyscallTrace,
		target: None,
		filter: Some("read".into()),
	};
	let config2 = ProbeConfig {
		probe_type: ProbeType::NetworkMonitor,
		target: None,
		filter: None,
	};

	let h1 = p.attach_probe(&config1).unwrap();
	let h2 = p.attach_probe(&config2).unwrap();

	let probes = p.list_probes().unwrap();
	assert_eq!(probes.len(), 2, "should have 2 active probes");

	p.detach_probe(h1).unwrap();
	p.detach_probe(h2).unwrap();

	let probes_after = p.list_probes().unwrap();
	assert_eq!(probes_after.len(), 0, "should have 0 active probes after detach");
}

#[test]
#[ignore]
fn double_detach_returns_not_found() {
	let p = platform();
	let config = ProbeConfig {
		probe_type: ProbeType::SyscallTrace,
		target: None,
		filter: None,
	};

	let handle = p.attach_probe(&config).unwrap();
	p.detach_probe(handle).unwrap();

	let result = p.detach_probe(handle);
	assert!(result.is_err(), "double detach should return error");
	let err = result.unwrap_err();
	assert!(
		matches!(err, mycelium_core::MyceliumError::NotFound(_)),
		"error should be NotFound, got: {err}"
	);
}

#[test]
#[ignore]
fn event_fields_reasonable() {
	let p = platform();
	let config = ProbeConfig {
		probe_type: ProbeType::SyscallTrace,
		target: Some(own_pid().to_string()),
		filter: None,
	};

	let handle = p.attach_probe(&config).unwrap();

	// Generate syscalls.
	let _ = std::fs::read_dir("/proc/self");
	thread::sleep(Duration::from_millis(500));

	let events = p.read_probe_events(&handle).unwrap();
	for event in &events {
		assert!(event.timestamp > 0, "timestamp should be non-zero");
		assert!(!event.process_name.is_empty(), "process_name should not be empty");
		assert_eq!(event.event_type, "syscall");
		// Details should contain syscall_nr= and a resolved name.
		assert!(
			event.details.contains("syscall_nr="),
			"details should contain syscall_nr="
		);
	}

	p.detach_probe(handle).unwrap();
}
