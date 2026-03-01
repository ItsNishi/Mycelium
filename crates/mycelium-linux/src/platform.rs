/// LinuxPlatform -- the primary Platform implementation for Linux.

use mycelium_core::error::Result;
use mycelium_core::platform::Platform;
use mycelium_core::types::*;

/// Linux backend using /proc, /sys, nix, and systemd D-Bus.
pub struct LinuxPlatform;

impl LinuxPlatform {
	pub fn new() -> Self {
		Self
	}
}

impl Default for LinuxPlatform {
	fn default() -> Self {
		Self::new()
	}
}

impl Platform for LinuxPlatform {
	// -- Process --

	fn list_processes(&self) -> Result<Vec<ProcessInfo>> {
		crate::process::list_processes()
	}

	fn inspect_process(&self, pid: u32) -> Result<ProcessInfo> {
		crate::process::inspect_process(pid)
	}

	fn process_resources(&self, pid: u32) -> Result<ProcessResource> {
		crate::process::process_resources(pid)
	}

	fn kill_process(&self, _pid: u32, _signal: Signal) -> Result<()> {
		Err(mycelium_core::MyceliumError::Unsupported(
			"write operations not implemented in Phase 1".into(),
		))
	}

	// -- Memory --

	fn memory_info(&self) -> Result<MemoryInfo> {
		crate::memory::memory_info()
	}

	fn process_memory(&self, pid: u32) -> Result<ProcessMemory> {
		crate::memory::process_memory(pid)
	}

	// -- Network --

	fn list_interfaces(&self) -> Result<Vec<NetworkInterface>> {
		crate::network::list_interfaces()
	}

	fn list_connections(&self) -> Result<Vec<Connection>> {
		crate::network::list_connections()
	}

	fn list_routes(&self) -> Result<Vec<Route>> {
		crate::network::list_routes()
	}

	fn list_open_ports(&self) -> Result<Vec<OpenPort>> {
		crate::network::list_open_ports()
	}

	fn list_firewall_rules(&self) -> Result<Vec<FirewallRule>> {
		crate::network::list_firewall_rules()
	}

	fn add_firewall_rule(&self, _rule: &FirewallRule) -> Result<()> {
		Err(mycelium_core::MyceliumError::Unsupported(
			"write operations not implemented in Phase 1".into(),
		))
	}

	fn remove_firewall_rule(&self, _rule_id: &str) -> Result<()> {
		Err(mycelium_core::MyceliumError::Unsupported(
			"write operations not implemented in Phase 1".into(),
		))
	}

	// -- Storage --

	fn list_disks(&self) -> Result<Vec<DiskInfo>> {
		crate::storage::list_disks()
	}

	fn list_partitions(&self) -> Result<Vec<Partition>> {
		crate::storage::list_partitions()
	}

	fn list_mounts(&self) -> Result<Vec<MountPoint>> {
		crate::storage::list_mounts()
	}

	fn io_stats(&self) -> Result<Vec<IoStats>> {
		crate::storage::io_stats()
	}

	// -- System --

	fn system_info(&self) -> Result<SystemInfo> {
		crate::system::system_info()
	}

	fn kernel_info(&self) -> Result<KernelInfo> {
		crate::system::kernel_info()
	}

	fn cpu_info(&self) -> Result<CpuInfo> {
		crate::system::cpu_info()
	}

	fn uptime(&self) -> Result<u64> {
		crate::system::uptime()
	}

	// -- Tuning --

	fn get_tunable(&self, key: &str) -> Result<TunableValue> {
		crate::tuning::get_tunable(key)
	}

	fn list_tunables(&self, prefix: &str) -> Result<Vec<TunableParam>> {
		crate::tuning::list_tunables(prefix)
	}

	fn set_tunable(&self, _key: &str, _value: &TunableValue) -> Result<TunableValue> {
		Err(mycelium_core::MyceliumError::Unsupported(
			"write operations not implemented in Phase 1".into(),
		))
	}

	// -- Services --

	fn list_services(&self) -> Result<Vec<ServiceInfo>> {
		crate::service::list_services()
	}

	fn service_status(&self, name: &str) -> Result<ServiceInfo> {
		crate::service::service_status(name)
	}

	fn service_action(&self, _name: &str, _action: ServiceAction) -> Result<()> {
		Err(mycelium_core::MyceliumError::Unsupported(
			"write operations not implemented in Phase 1".into(),
		))
	}

	// -- Logs --

	fn read_logs(&self, query: &LogQuery) -> Result<Vec<LogEntry>> {
		crate::service::read_logs(query)
	}

	// -- Security --

	fn list_users(&self) -> Result<Vec<UserInfo>> {
		crate::security::list_users()
	}

	fn list_groups(&self) -> Result<Vec<GroupInfo>> {
		crate::security::list_groups()
	}

	fn list_kernel_modules(&self) -> Result<Vec<KernelModule>> {
		crate::security::list_kernel_modules()
	}

	fn security_status(&self) -> Result<SecurityStatus> {
		crate::security::security_status()
	}
}
