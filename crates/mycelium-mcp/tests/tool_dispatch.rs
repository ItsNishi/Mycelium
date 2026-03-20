//! MCP tool dispatch integration tests.
//!
//! Uses a mock Platform implementation returning canned data, and a
//! CapturingAuditLog to verify audit entries.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use mycelium_core::audit::{AuditEntry, AuditLog, AuditOutcome};
use mycelium_core::error::{MyceliumError, Result};
use mycelium_core::platform::*;
use mycelium_core::policy::config::parse_policy_toml;
use mycelium_core::policy::{Policy, RateLimit};
use mycelium_core::types::*;

use mycelium_mcp::MyceliumMcpService;

// ---------------------------------------------------------------------------
// Mock Platform
// ---------------------------------------------------------------------------

struct MockPlatform;

impl ProcessPlatform for MockPlatform {
	fn list_processes(&self) -> Result<Vec<ProcessInfo>> {
		Ok(vec![ProcessInfo {
			pid: 1,
			ppid: 0,
			name: "init".into(),
			state: ProcessState::Running,
			user: "root".into(),
			uid: 0,
			threads: 1,
			cpu_percent: 0.0,
			memory_bytes: 4096,
			command: "/sbin/init".into(),
			start_time: 0,
		}])
	}

	fn inspect_process(&self, pid: u32) -> Result<ProcessInfo> {
		if pid == 1 {
			Ok(ProcessInfo {
				pid: 1,
				ppid: 0,
				name: "init".into(),
				state: ProcessState::Running,
				user: "root".into(),
				uid: 0,
				threads: 1,
				cpu_percent: 0.0,
				memory_bytes: 4096,
				command: "/sbin/init".into(),
				start_time: 0,
			})
		} else {
			Err(MyceliumError::NotFound(format!("pid {pid}")))
		}
	}

	fn process_resources(&self, pid: u32) -> Result<ProcessResource> {
		Ok(ProcessResource {
			pid,
			cpu_percent: 1.0,
			memory_bytes: 1024,
			memory_percent: 0.01,
			virtual_memory_bytes: 4096,
			open_fds: 10,
			threads: 1,
			read_bytes: 0,
			write_bytes: 0,
		})
	}

	fn kill_process(&self, _pid: u32, _signal: Signal) -> Result<()> {
		Ok(())
	}
}

impl MemoryPlatform for MockPlatform {
	fn memory_info(&self) -> Result<MemoryInfo> {
		Ok(MemoryInfo {
			total_bytes: 16 * 1024 * 1024 * 1024,
			available_bytes: 8 * 1024 * 1024 * 1024,
			used_bytes: 8 * 1024 * 1024 * 1024,
			free_bytes: 4 * 1024 * 1024 * 1024,
			buffers_bytes: 512 * 1024 * 1024,
			cached_bytes: 2 * 1024 * 1024 * 1024,
			swap: SwapInfo {
				total_bytes: 4 * 1024 * 1024 * 1024,
				used_bytes: 0,
				free_bytes: 4 * 1024 * 1024 * 1024,
			},
		})
	}

	fn process_memory(&self, pid: u32) -> Result<ProcessMemory> {
		Ok(ProcessMemory {
			pid,
			rss_bytes: 1024,
			virtual_bytes: 4096,
			shared_bytes: 512,
			text_bytes: 256,
			data_bytes: 128,
		})
	}

	fn process_memory_maps(&self, _pid: u32) -> Result<Vec<MemoryRegion>> {
		Ok(vec![])
	}

	fn read_process_memory(&self, _pid: u32, _addr: u64, size: usize) -> Result<Vec<u8>> {
		Ok(vec![0u8; size])
	}

	fn write_process_memory(&self, _pid: u32, _addr: u64, data: &[u8]) -> Result<usize> {
		Ok(data.len())
	}
}

impl NetworkPlatform for MockPlatform {
	fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
		Ok(vec![])
	}
	fn list_connections(&self) -> Result<Vec<Connection>> {
		Ok(vec![])
	}
	fn list_routes(&self) -> Result<Vec<Route>> {
		Ok(vec![])
	}
	fn list_open_ports(&self) -> Result<Vec<OpenPort>> {
		Ok(vec![])
	}
	fn list_firewall_rules(&self) -> Result<Vec<FirewallRule>> {
		Ok(vec![])
	}
	fn add_firewall_rule(&self, _rule: &FirewallRule) -> Result<()> {
		Ok(())
	}
	fn remove_firewall_rule(&self, _id: &str) -> Result<()> {
		Ok(())
	}
}

impl StoragePlatform for MockPlatform {
	fn list_disks(&self) -> Result<Vec<DiskInfo>> {
		Ok(vec![])
	}
	fn list_partitions(&self) -> Result<Vec<Partition>> {
		Ok(vec![])
	}
	fn list_mounts(&self) -> Result<Vec<MountPoint>> {
		Ok(vec![])
	}
	fn io_stats(&self) -> Result<Vec<IoStats>> {
		Ok(vec![])
	}
}

impl SystemPlatform for MockPlatform {
	fn system_info(&self) -> Result<SystemInfo> {
		Ok(SystemInfo {
			hostname: "mock-host".into(),
			os_name: "Linux".into(),
			os_version: "6.0.0-test".into(),
			architecture: "x86_64".into(),
			uptime_seconds: 12345,
			boot_time: 0,
		})
	}
	fn kernel_info(&self) -> Result<KernelInfo> {
		Ok(KernelInfo {
			version: "6.0.0-test".into(),
			release: "6.0.0-test".into(),
			architecture: "x86_64".into(),
			command_line: String::new(),
		})
	}
	fn cpu_info(&self) -> Result<CpuInfo> {
		Ok(CpuInfo {
			model_name: "Test CPU".into(),
			cores_physical: 4,
			cores_logical: 8,
			frequency_mhz: 3000.0,
			cache_size_kb: 8192,
			load_average: [0.5, 0.3, 0.1],
			usage_percent: 5.0,
		})
	}
	fn uptime(&self) -> Result<u64> {
		Ok(12345)
	}
}

impl TuningPlatform for MockPlatform {
	fn get_tunable(&self, _key: &str) -> Result<TunableValue> {
		Ok(TunableValue::String("mock-value".into()))
	}
	fn list_tunables(&self, _prefix: &str) -> Result<Vec<TunableParam>> {
		Ok(vec![])
	}
	fn set_tunable(&self, _key: &str, _val: &TunableValue) -> Result<TunableValue> {
		Ok(TunableValue::String("old-value".into()))
	}
}

impl ServicePlatform for MockPlatform {
	fn list_services(&self) -> Result<Vec<ServiceInfo>> {
		Ok(vec![])
	}
	fn service_status(&self, _name: &str) -> Result<ServiceInfo> {
		Err(MyceliumError::NotFound("service".into()))
	}
	fn service_action(&self, _name: &str, _action: ServiceAction) -> Result<()> {
		Ok(())
	}
	fn read_logs(&self, _query: &LogQuery) -> Result<Vec<LogEntry>> {
		Ok(vec![])
	}
}

impl SecurityPlatform for MockPlatform {
	fn list_users(&self) -> Result<Vec<UserInfo>> {
		Ok(vec![])
	}
	fn list_groups(&self) -> Result<Vec<GroupInfo>> {
		Ok(vec![])
	}
	fn list_kernel_modules(&self) -> Result<Vec<KernelModule>> {
		Ok(vec![])
	}
	fn security_status(&self) -> Result<SecurityStatus> {
		Ok(SecurityStatus {
			selinux: None,
			apparmor: None,
			firewall_active: false,
			root_login_allowed: false,
			password_auth_ssh: false,
		})
	}
}

// ---------------------------------------------------------------------------
// Capturing Audit Log
// ---------------------------------------------------------------------------

struct CapturingAuditLog {
	entries: Mutex<Vec<AuditEntry>>,
}

impl CapturingAuditLog {
	fn new() -> Self {
		Self {
			entries: Mutex::new(Vec::new()),
		}
	}

	fn entries(&self) -> Vec<AuditEntry> {
		self.entries.lock().unwrap().clone()
	}
}

impl AuditLog for CapturingAuditLog {
	fn log(&self, entry: &AuditEntry) {
		self.entries.lock().unwrap().push(entry.clone());
	}
}

// ---------------------------------------------------------------------------
// Helper: build service
// ---------------------------------------------------------------------------

fn make_service(policy: Policy, agent: &str) -> (MyceliumMcpService, Arc<CapturingAuditLog>) {
	let audit = Arc::new(CapturingAuditLog::new());
	let svc = MyceliumMcpService::new(
		Arc::new(MockPlatform),
		Arc::new(policy),
		audit.clone() as Arc<dyn AuditLog>,
		agent.to_string(),
	);
	(svc, audit)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn read_tool_allowed_by_default() {
	let (svc, audit) = make_service(Policy::default(), "test-agent");

	// check_policy should return None (allowed).
	let result = svc.check_policy("process_list", None);
	assert!(result.is_none(), "default policy should allow process_list");

	// No audit entry for allowed checks that aren't logged yet.
	assert!(audit.entries().is_empty());
}

#[tokio::test]
async fn write_tool_denied_for_readonly() {
	let toml = r#"
[profiles.readonly-bot]
role = "read-only"
"#;
	let policy = parse_policy_toml(toml).unwrap();
	let (svc, audit) = make_service(policy, "readonly-bot");

	let result = svc.check_policy("process_kill", None);
	assert!(result.is_some(), "readonly should deny process_kill");

	// Verify audit logged the denial.
	let entries = audit.entries();
	assert_eq!(entries.len(), 1);
	assert_eq!(entries[0].tool, "process_kill");
	assert_eq!(entries[0].outcome, AuditOutcome::Denied);
	assert!(!entries[0].allowed);
}

#[tokio::test]
async fn rate_limit_blocks_after_max() {
	let mut rate_limits = HashMap::new();
	rate_limits.insert(
		"process_kill".into(),
		RateLimit {
			max_calls: 2,
			window_secs: 60,
		},
	);

	let policy = Policy {
		rate_limits,
		..Policy::default()
	};

	let (svc, audit) = make_service(policy, "test-agent");

	// First two should pass.
	assert!(svc.check_rate_limit("process_kill").is_none());
	assert!(svc.check_rate_limit("process_kill").is_none());

	// Third should be rate limited.
	let result = svc.check_rate_limit("process_kill");
	assert!(result.is_some(), "third call should be rate limited");

	// Verify audit log.
	let entries = audit.entries();
	assert_eq!(entries.len(), 1);
	assert_eq!(entries[0].outcome, AuditOutcome::RateLimited);
}

#[tokio::test]
async fn audit_log_records_success() {
	let (svc, audit) = make_service(Policy::default(), "test-agent");

	svc.log_success("process_list", None);

	let entries = audit.entries();
	assert_eq!(entries.len(), 1);
	assert_eq!(entries[0].tool, "process_list");
	assert_eq!(entries[0].outcome, AuditOutcome::Success);
	assert!(entries[0].allowed);
}

#[tokio::test]
async fn audit_log_records_deny() {
	let toml = r#"
[profiles.reader]
role = "read-only"
"#;
	let policy = parse_policy_toml(toml).unwrap();
	let (svc, audit) = make_service(policy, "reader");

	let _ = svc.check_policy("tuning_set", None);

	let entries = audit.entries();
	assert_eq!(entries.len(), 1);
	assert_eq!(entries[0].tool, "tuning_set");
	assert_eq!(entries[0].outcome, AuditOutcome::Denied);
	assert!(!entries[0].allowed);
}

#[tokio::test]
async fn dry_run_returns_notice() {
	let toml = r#"
[global]
dry_run = true

[[global.rules]]
action = "allow"
target = "all"
"#;
	let policy = parse_policy_toml(toml).unwrap();
	let (svc, _audit) = make_service(policy, "test-agent");

	assert!(svc.is_dry_run(), "policy should be in dry-run mode");
}

#[tokio::test]
async fn probe_tools_without_platform() {
	let (svc, _audit) = make_service(Policy::default(), "test-agent");

	// probe_platform is None by default.
	assert!(
		svc.probe_platform().is_none(),
		"probe_platform should be None without explicit setup"
	);
}
