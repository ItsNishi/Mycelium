//! The core Platform trait that all OS backends implement.
//!
//! Split into sub-traits by functional category. The composite `Platform`
//! supertrait provides a blanket impl so `Arc<dyn Platform>` continues to work.

use crate::error::Result;
use crate::types::*;

// ---------------------------------------------------------------------------
// Sub-trait: Process
// ---------------------------------------------------------------------------

/// Process listing, inspection, and signalling.
pub trait ProcessPlatform: Send + Sync {
	/// List all running processes.
	fn list_processes(&self) -> Result<Vec<ProcessInfo>>;

	/// Get detailed info for a single process.
	fn inspect_process(&self, pid: u32) -> Result<ProcessInfo>;

	/// Get resource usage for a single process.
	fn process_resources(&self, pid: u32) -> Result<ProcessResource>;

	/// Send a signal to a process. **WRITE**
	fn kill_process(&self, pid: u32, signal: Signal) -> Result<()>;

	/// List threads belonging to a process.
	fn list_process_threads(&self, pid: u32) -> Result<Vec<ThreadInfo>> {
		let _ = pid;
		Err(crate::error::MyceliumError::Unsupported(
			"list_process_threads is not supported on this platform".to_string(),
		))
	}

	/// List modules (DLLs / shared libraries) loaded by a process.
	fn list_process_modules(&self, pid: u32) -> Result<Vec<ProcessModule>> {
		let _ = pid;
		Err(crate::error::MyceliumError::Unsupported(
			"list_process_modules is not supported on this platform".to_string(),
		))
	}

	/// Read the environment variables of a process as key-value pairs.
	fn process_environment(&self, pid: u32) -> Result<Vec<(String, String)>> {
		let _ = pid;
		Err(crate::error::MyceliumError::Unsupported(
			"process_environment is not supported on this platform".to_string(),
		))
	}

	/// List privileges held by a process token.
	fn list_process_privileges(&self, pid: u32) -> Result<Vec<PrivilegeInfo>> {
		let _ = pid;
		Err(crate::error::MyceliumError::Unsupported(
			"list_process_privileges is not supported on this platform".to_string(),
		))
	}

	/// List open handles (files, registry keys, mutexes, etc.) for a process.
	fn list_process_handles(&self, pid: u32) -> Result<Vec<HandleInfo>> {
		let _ = pid;
		Err(crate::error::MyceliumError::Unsupported(
			"list_process_handles is not supported on this platform".to_string(),
		))
	}

	/// Parse PE headers of a process or file.
	fn inspect_pe(&self, target: &PeTarget) -> Result<PeInfo> {
		let _ = target;
		Err(crate::error::MyceliumError::Unsupported(
			"inspect_pe is not supported on this platform".to_string(),
		))
	}

	/// Parse ELF headers of a process binary or file.
	fn inspect_elf(&self, target: &ElfTarget) -> Result<ElfInfo> {
		let _ = target;
		Err(crate::error::MyceliumError::Unsupported(
			"inspect_elf is not supported on this platform".to_string(),
		))
	}

	/// Inspect process token security details (integrity, groups, elevation, impersonation).
	fn inspect_process_token(&self, pid: u32) -> Result<TokenInfo> {
		let _ = pid;
		Err(crate::error::MyceliumError::Unsupported(
			"inspect_process_token is not supported on this platform".to_string(),
		))
	}
}

// ---------------------------------------------------------------------------
// Sub-trait: Memory
// ---------------------------------------------------------------------------

/// System and per-process memory inspection, plus raw read/write/protect.
pub trait MemoryPlatform: Send + Sync {
	/// Get system-wide memory information.
	fn memory_info(&self) -> Result<MemoryInfo>;

	/// Get memory details for a single process.
	fn process_memory(&self, pid: u32) -> Result<ProcessMemory>;

	/// List virtual memory regions for a process (`/proc/<pid>/maps`).
	fn process_memory_maps(&self, pid: u32) -> Result<Vec<MemoryRegion>>;

	/// Read raw bytes from a process's virtual memory. **SENSITIVE**
	fn read_process_memory(&self, pid: u32, address: u64, size: usize) -> Result<Vec<u8>>;

	/// Write raw bytes to a process's virtual memory. Returns bytes written. **WRITE**
	fn write_process_memory(&self, pid: u32, address: u64, data: &[u8]) -> Result<usize>;

	/// Search process memory for byte patterns, UTF-8 or UTF-16 strings.
	fn search_process_memory(
		&self,
		pid: u32,
		pattern: &SearchPattern,
		options: &MemorySearchOptions,
	) -> Result<Vec<MemoryMatch>> {
		let _ = (pid, pattern, options);
		Err(crate::error::MyceliumError::Unsupported(
			"search_process_memory is not supported on this platform".to_string(),
		))
	}

	/// Change memory protection on a region of a process's virtual address space.
	/// Returns the previous protection as a string (e.g. `"rwx"`, `"r--"`).
	fn protect_process_memory(
		&self,
		pid: u32,
		address: u64,
		size: usize,
		protection: &str,
	) -> Result<String> {
		let _ = (pid, address, size, protection);
		Err(crate::error::MyceliumError::Unsupported(
			"protect_process_memory is not supported on this platform".to_string(),
		))
	}
}

// ---------------------------------------------------------------------------
// Sub-trait: Network
// ---------------------------------------------------------------------------

/// Network interfaces, connections, routing, and firewall management.
pub trait NetworkPlatform: Send + Sync {
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
}

// ---------------------------------------------------------------------------
// Sub-trait: Storage
// ---------------------------------------------------------------------------

/// Disk, partition, mount, and I/O statistics.
pub trait StoragePlatform: Send + Sync {
	/// List physical disks.
	fn list_disks(&self) -> Result<Vec<DiskInfo>>;

	/// List partitions.
	fn list_partitions(&self) -> Result<Vec<Partition>>;

	/// List mounted filesystems.
	fn list_mounts(&self) -> Result<Vec<MountPoint>>;

	/// Get I/O statistics per block device.
	fn io_stats(&self) -> Result<Vec<IoStats>>;
}

// ---------------------------------------------------------------------------
// Sub-trait: System
// ---------------------------------------------------------------------------

/// High-level system, kernel, CPU info and uptime.
pub trait SystemPlatform: Send + Sync {
	/// Get high-level system information.
	fn system_info(&self) -> Result<SystemInfo>;

	/// Get kernel version and build info.
	fn kernel_info(&self) -> Result<KernelInfo>;

	/// Get CPU information and load.
	fn cpu_info(&self) -> Result<CpuInfo>;

	/// Get system uptime in seconds.
	fn uptime(&self) -> Result<u64>;
}

// ---------------------------------------------------------------------------
// Sub-trait: Tuning
// ---------------------------------------------------------------------------

/// Kernel tunable (sysctl / registry) access.
pub trait TuningPlatform: Send + Sync {
	/// Read a single kernel tunable.
	fn get_tunable(&self, key: &str) -> Result<TunableValue>;

	/// List tunables matching a prefix.
	fn list_tunables(&self, prefix: &str) -> Result<Vec<TunableParam>>;

	/// Set a kernel tunable. Returns the previous value. **WRITE**
	fn set_tunable(&self, key: &str, value: &TunableValue) -> Result<TunableValue>;
}

// ---------------------------------------------------------------------------
// Sub-trait: Service (includes Logs)
// ---------------------------------------------------------------------------

/// Service management and log reading.
pub trait ServicePlatform: Send + Sync {
	/// List all known services.
	fn list_services(&self) -> Result<Vec<ServiceInfo>>;

	/// Get status of a single service.
	fn service_status(&self, name: &str) -> Result<ServiceInfo>;

	/// Perform an action on a service. **WRITE**
	fn service_action(&self, name: &str, action: ServiceAction) -> Result<()>;

	/// Read log entries matching a query.
	fn read_logs(&self, query: &LogQuery) -> Result<Vec<LogEntry>>;
}

// ---------------------------------------------------------------------------
// Sub-trait: Security
// ---------------------------------------------------------------------------

/// Users, groups, kernel modules, and security posture.
pub trait SecurityPlatform: Send + Sync {
	/// List system user accounts.
	fn list_users(&self) -> Result<Vec<UserInfo>>;

	/// List system groups.
	fn list_groups(&self) -> Result<Vec<GroupInfo>>;

	/// List loaded kernel modules.
	fn list_kernel_modules(&self) -> Result<Vec<KernelModule>>;

	/// Get overall security status.
	fn security_status(&self) -> Result<SecurityStatus>;

	/// Scan Windows persistence mechanisms (registry, services, tasks, startup, WMI, COM).
	fn list_persistence_entries(&self) -> Result<Vec<PersistenceEntry>> {
		Err(crate::error::MyceliumError::Unsupported(
			"list_persistence_entries is not supported on this platform".to_string(),
		))
	}

	/// Detect API hooks (inline, IAT, EAT) in a process.
	fn detect_hooks(&self, pid: u32) -> Result<Vec<HookInfo>> {
		let _ = pid;
		Err(crate::error::MyceliumError::Unsupported(
			"detect_hooks is not supported on this platform".to_string(),
		))
	}
}

// ---------------------------------------------------------------------------
// Composite supertrait
// ---------------------------------------------------------------------------

/// Synchronous interface to OS kernel data and controls.
///
/// `/proc` reads are kernel-backed memory operations (microseconds).
/// The async MCP layer wraps calls with `spawn_blocking`.
///
/// This is a composite supertrait -- any type implementing all 8 sub-traits
/// automatically implements `Platform` via the blanket impl below.
pub trait Platform:
	ProcessPlatform
	+ MemoryPlatform
	+ NetworkPlatform
	+ StoragePlatform
	+ SystemPlatform
	+ TuningPlatform
	+ ServicePlatform
	+ SecurityPlatform
{
}

impl<T> Platform for T where
	T: ProcessPlatform
		+ MemoryPlatform
		+ NetworkPlatform
		+ StoragePlatform
		+ SystemPlatform
		+ TuningPlatform
		+ ServicePlatform
		+ SecurityPlatform
{
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
