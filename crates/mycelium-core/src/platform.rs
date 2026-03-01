//! The core Platform trait that all OS backends implement.

use crate::error::Result;
use crate::types::*;

/// Synchronous interface to OS kernel data and controls.
///
/// `/proc` reads are kernel-backed memory operations (microseconds).
/// The async MCP layer wraps calls with `spawn_blocking`.
pub trait Platform: Send + Sync {
	// -- Process (4 methods) --

	/// List all running processes.
	fn list_processes(&self) -> Result<Vec<ProcessInfo>>;

	/// Get detailed info for a single process.
	fn inspect_process(&self, pid: u32) -> Result<ProcessInfo>;

	/// Get resource usage for a single process.
	fn process_resources(&self, pid: u32) -> Result<ProcessResource>;

	/// Send a signal to a process. **WRITE**
	fn kill_process(&self, pid: u32, signal: Signal) -> Result<()>;

	// -- Memory (2 methods) --

	/// Get system-wide memory information.
	fn memory_info(&self) -> Result<MemoryInfo>;

	/// Get memory details for a single process.
	fn process_memory(&self, pid: u32) -> Result<ProcessMemory>;

	// -- Network (7 methods) --

	/// List network interfaces with stats.
	fn list_interfaces(&self) -> Result<Vec<NetworkInterface>>;

	/// List active network connections.
	fn list_connections(&self) -> Result<Vec<Connection>>;

	/// List routing table entries.
	fn list_routes(&self) -> Result<Vec<Route>>;

	/// List open (listening) ports.
	fn list_open_ports(&self) -> Result<Vec<OpenPort>>;

	/// List firewall rules.
	fn list_firewall_rules(&self) -> Result<Vec<FirewallRule>>;

	/// Add a firewall rule. **WRITE**
	fn add_firewall_rule(&self, rule: &FirewallRule) -> Result<()>;

	/// Remove a firewall rule by id. **WRITE**
	fn remove_firewall_rule(&self, rule_id: &str) -> Result<()>;

	// -- Storage (4 methods) --

	/// List physical disks.
	fn list_disks(&self) -> Result<Vec<DiskInfo>>;

	/// List partitions.
	fn list_partitions(&self) -> Result<Vec<Partition>>;

	/// List mounted filesystems.
	fn list_mounts(&self) -> Result<Vec<MountPoint>>;

	/// Get I/O statistics per block device.
	fn io_stats(&self) -> Result<Vec<IoStats>>;

	// -- System (4 methods) --

	/// Get high-level system information.
	fn system_info(&self) -> Result<SystemInfo>;

	/// Get kernel version and build info.
	fn kernel_info(&self) -> Result<KernelInfo>;

	/// Get CPU information and load.
	fn cpu_info(&self) -> Result<CpuInfo>;

	/// Get system uptime in seconds.
	fn uptime(&self) -> Result<u64>;

	// -- Tuning (3 methods) --

	/// Read a single kernel tunable.
	fn get_tunable(&self, key: &str) -> Result<TunableValue>;

	/// List tunables matching a prefix.
	fn list_tunables(&self, prefix: &str) -> Result<Vec<TunableParam>>;

	/// Set a kernel tunable. Returns the previous value. **WRITE**
	fn set_tunable(&self, key: &str, value: &TunableValue) -> Result<TunableValue>;

	// -- Services (3 methods) --

	/// List all known services.
	fn list_services(&self) -> Result<Vec<ServiceInfo>>;

	/// Get status of a single service.
	fn service_status(&self, name: &str) -> Result<ServiceInfo>;

	/// Perform an action on a service. **WRITE**
	fn service_action(&self, name: &str, action: ServiceAction) -> Result<()>;

	// -- Logs (1 method) --

	/// Read log entries matching a query.
	fn read_logs(&self, query: &LogQuery) -> Result<Vec<LogEntry>>;

	// -- Security (4 methods) --

	/// List system user accounts.
	fn list_users(&self) -> Result<Vec<UserInfo>>;

	/// List system groups.
	fn list_groups(&self) -> Result<Vec<GroupInfo>>;

	/// List loaded kernel modules.
	fn list_kernel_modules(&self) -> Result<Vec<KernelModule>>;

	/// Get overall security status.
	fn security_status(&self) -> Result<SecurityStatus>;
}

/// Extended trait for eBPF probe support (Linux only).
///
/// Separate from `Platform` so Windows does not need to stub these methods.
pub trait ProbePlatform: Platform {
	/// Attach an eBPF probe.
	fn attach_probe(&self, config: &ProbeConfig) -> Result<ProbeHandle>;

	/// Detach a running probe.
	fn detach_probe(&self, handle: ProbeHandle) -> Result<()>;

	/// List active probes.
	fn list_probes(&self) -> Result<Vec<ProbeInfo>>;

	/// Read events from a probe.
	fn read_probe_events(&self, handle: &ProbeHandle) -> Result<Vec<ProbeEvent>>;
}
