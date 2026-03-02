//! Read-only integration tests for LinuxPlatform.
//!
//! These tests exercise trait methods against the live system. None require
//! root or elevated privileges -- they only read publicly available system
//! state. Safe to run in CI.

use mycelium_core::platform::*;
use mycelium_linux::LinuxPlatform;

fn platform() -> LinuxPlatform {
	LinuxPlatform::new()
}

fn own_pid() -> u32 {
	std::process::id()
}

// ---------------------------------------------------------------------------
// Process
// ---------------------------------------------------------------------------

#[test]
fn list_processes_is_non_empty() {
	let procs = platform().list_processes().unwrap();
	assert!(!procs.is_empty(), "process list should not be empty");
}

#[test]
fn list_processes_contains_our_pid() {
	let procs = platform().list_processes().unwrap();
	let pid = own_pid();
	assert!(
		procs.iter().any(|p| p.pid == pid),
		"process list should contain our PID ({pid})"
	);
}

#[test]
fn inspect_process_self() {
	let info = platform().inspect_process(own_pid()).unwrap();
	assert_eq!(info.pid, own_pid());
	assert!(!info.name.is_empty(), "process name should not be empty");
}

#[test]
fn process_resources_self() {
	let res = platform().process_resources(own_pid()).unwrap();
	assert!(res.memory_bytes > 0, "memory_bytes should be > 0");
}

#[test]
fn process_environment_has_path() {
	let env = platform().process_environment(own_pid()).unwrap();
	assert!(
		env.iter().any(|(k, _)| k == "PATH"),
		"environment should contain PATH"
	);
}

#[test]
fn list_process_threads_at_least_one() {
	let threads = platform().list_process_threads(own_pid()).unwrap();
	assert!(
		!threads.is_empty(),
		"should have at least one thread (the main thread)"
	);
}

#[test]
fn list_process_modules_self() {
	let modules = platform().list_process_modules(own_pid()).unwrap();
	assert!(
		!modules.is_empty(),
		"should have at least one mapped module"
	);
}

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------

#[test]
fn memory_info_total_positive() {
	let mem = platform().memory_info().unwrap();
	assert!(mem.total_bytes > 0, "total memory should be > 0");
}

#[test]
fn memory_info_available_within_total() {
	let mem = platform().memory_info().unwrap();
	assert!(
		mem.available_bytes <= mem.total_bytes,
		"available ({}) should be <= total ({})",
		mem.available_bytes,
		mem.total_bytes
	);
}

#[test]
fn process_memory_self_rss_positive() {
	let mem = platform().process_memory(own_pid()).unwrap();
	assert!(mem.rss_bytes > 0, "RSS should be > 0 for our own process");
}

#[test]
fn process_memory_maps_has_regions() {
	let maps = platform().process_memory_maps(own_pid()).unwrap();
	assert!(!maps.is_empty(), "should have at least one memory region");

	let has_named = maps.iter().any(|r| {
		r.pathname
			.as_ref()
			.is_some_and(|p| p.contains("heap") || p.contains("stack"))
	});
	assert!(has_named, "should have heap or stack region");
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

#[test]
fn list_interfaces_has_lo() {
	let ifaces = platform().list_interfaces().unwrap();
	assert!(
		ifaces.iter().any(|i| i.name == "lo"),
		"interface list should contain 'lo'"
	);
}

#[test]
fn list_connections_ok() {
	let _ = platform().list_connections().unwrap();
}

#[test]
fn list_routes_non_empty() {
	let routes = platform().list_routes().unwrap();
	assert!(!routes.is_empty(), "routing table should not be empty");
}

#[test]
fn list_open_ports_ok() {
	let _ = platform().list_open_ports().unwrap();
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

#[test]
fn list_disks_ok() {
	let _ = platform().list_disks().unwrap();
}

#[test]
fn list_mounts_has_root() {
	let mounts = platform().list_mounts().unwrap();
	assert!(
		mounts.iter().any(|m| m.mount_path == "/"),
		"mounts should contain '/'"
	);
}

#[test]
fn list_partitions_ok() {
	let _ = platform().list_partitions().unwrap();
}

#[test]
fn io_stats_ok() {
	let _ = platform().io_stats().unwrap();
}

// ---------------------------------------------------------------------------
// System
// ---------------------------------------------------------------------------

#[test]
fn system_info_hostname_non_empty() {
	let info = platform().system_info().unwrap();
	assert!(
		!info.hostname.is_empty(),
		"hostname should not be empty"
	);
}

#[test]
fn kernel_info_release_non_empty() {
	let info = platform().kernel_info().unwrap();
	assert!(
		!info.release.is_empty(),
		"kernel release should not be empty"
	);
	// Release looks like "6.19.2-1-default".
	assert!(
		info.release.contains('.'),
		"kernel release '{}' should contain a dot",
		info.release
	);
}

#[test]
fn cpu_info_cores_positive() {
	let info = platform().cpu_info().unwrap();
	assert!(info.cores_physical > 0, "physical core count should be > 0");
}

#[test]
fn uptime_positive() {
	let up = platform().uptime().unwrap();
	assert!(up > 0, "uptime should be > 0 seconds");
}

// ---------------------------------------------------------------------------
// Security
// ---------------------------------------------------------------------------

#[test]
fn list_users_has_root() {
	let users = platform().list_users().unwrap();
	assert!(
		users.iter().any(|u| u.uid == 0),
		"user list should contain uid 0 (root)"
	);
}

#[test]
fn list_groups_non_empty() {
	let groups = platform().list_groups().unwrap();
	assert!(!groups.is_empty(), "group list should not be empty");
}

#[test]
fn list_kernel_modules_ok() {
	let _ = platform().list_kernel_modules().unwrap();
}

#[test]
fn security_status_ok() {
	let _ = platform().security_status().unwrap();
}

#[test]
fn list_persistence_entries_ok() {
	let _ = platform().list_persistence_entries().unwrap();
}

// ---------------------------------------------------------------------------
// Tuning
// ---------------------------------------------------------------------------

#[test]
fn list_tunables_net_non_empty() {
	let tunables = platform().list_tunables("net").unwrap();
	assert!(
		!tunables.is_empty(),
		"net tunables should not be empty"
	);
}

#[test]
fn get_tunable_kernel_hostname_matches() {
	let val = platform().get_tunable("kernel.hostname").unwrap();
	let sys_info = platform().system_info().unwrap();
	let tunable_str = match val {
		mycelium_core::types::TunableValue::String(s) => s,
		other => panic!("expected string tunable, got {other:?}"),
	};
	assert_eq!(
		tunable_str.trim(),
		sys_info.hostname,
		"kernel.hostname tunable should match system hostname"
	);
}
