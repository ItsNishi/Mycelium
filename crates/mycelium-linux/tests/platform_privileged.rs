//! Privileged integration tests for LinuxPlatform.
//!
//! All tests are `#[ignore]` -- run with `sudo -E cargo test --test platform_privileged -- --ignored`.
//! These require root or CAP_SYS_PTRACE / CAP_NET_ADMIN.

use std::process::Command;

use mycelium_core::platform::*;
use mycelium_core::types::*;
use mycelium_linux::LinuxPlatform;

fn platform() -> LinuxPlatform {
	LinuxPlatform::new()
}

#[test]
#[ignore]
fn read_write_process_memory() {
	// Spawn a child that sleeps. We'll read/write its memory via ptrace.
	let mut child = Command::new("sleep")
		.arg("60")
		.spawn()
		.expect("failed to spawn sleep");

	let pid = child.id();

	// Give the child time to start.
	std::thread::sleep(std::time::Duration::from_millis(200));

	// Read memory maps to find a readable+writable region.
	let maps = platform().process_memory_maps(pid).unwrap();
	let readable = maps
		.iter()
		.find(|r| r.permissions.contains('r') && r.permissions.contains('w'))
		.expect("should find a readable+writable region");

	let addr = readable.start_address;

	// Read some bytes.
	let data = platform().read_process_memory(pid, addr, 8).unwrap();
	assert_eq!(data.len(), 8);

	// Write a known pattern and read it back.
	let pattern = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
	let written = platform().write_process_memory(pid, addr, &pattern).unwrap();
	assert_eq!(written, 8);

	let readback = platform().read_process_memory(pid, addr, 8).unwrap();
	assert_eq!(readback, pattern);

	// Clean up.
	child.kill().ok();
	child.wait().ok();
}

#[test]
#[ignore]
fn kill_process_with_term() {
	let mut child = Command::new("sleep")
		.arg("60")
		.spawn()
		.expect("failed to spawn sleep");

	let pid = child.id();
	std::thread::sleep(std::time::Duration::from_millis(100));

	platform().kill_process(pid, Signal::Term).unwrap();

	let status = child.wait().expect("failed to wait for child");
	assert!(!status.success());
}

#[test]
#[ignore]
fn set_tunable_roundtrip() {
	let key = "net.ipv4.ip_default_ttl";
	let original = platform().get_tunable(key).unwrap();

	// Set to a different value.
	let test_val = TunableValue::String("42".into());
	let _prev = platform().set_tunable(key, &test_val).unwrap();

	// Verify the change.
	let current = platform().get_tunable(key).unwrap();
	match &current {
		TunableValue::String(s) => assert_eq!(s.trim(), "42"),
		other => panic!("expected string tunable, got {other:?}"),
	}

	// Restore original.
	platform().set_tunable(key, &original).unwrap();

	// Verify restoration.
	let restored = platform().get_tunable(key).unwrap();
	match (&original, &restored) {
		(TunableValue::String(a), TunableValue::String(b)) => {
			assert_eq!(a.trim(), b.trim());
		}
		_ => panic!("tunable type mismatch after restore"),
	}
}

#[test]
#[ignore]
fn firewall_add_remove() {
	let rule = FirewallRule {
		id: String::new(),
		chain: "input".into(),
		protocol: Some("tcp".into()),
		source: None,
		destination: None,
		port: Some(59999),
		action: FirewallAction::Drop,
		comment: Some("mycelium-test".into()),
	};

	// Add the rule.
	platform().add_firewall_rule(&rule).unwrap();

	// List and verify it's there.
	let rules = platform().list_firewall_rules().unwrap();
	let found = rules.iter().any(|r| {
		r.comment.as_deref() == Some("mycelium-test") || r.port == Some(59999)
	});
	assert!(found, "added firewall rule should be listed");

	// Remove by finding the ID.
	let rule_to_remove = rules
		.iter()
		.find(|r| r.comment.as_deref() == Some("mycelium-test") || r.port == Some(59999))
		.expect("should find the rule to remove");

	platform().remove_firewall_rule(&rule_to_remove.id).unwrap();

	// Verify removal.
	let rules_after = platform().list_firewall_rules().unwrap();
	let still_found = rules_after.iter().any(|r| {
		r.comment.as_deref() == Some("mycelium-test") || r.port == Some(59999)
	});
	assert!(!still_found, "removed firewall rule should no longer be listed");
}
