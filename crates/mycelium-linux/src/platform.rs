//! LinuxPlatform -- the primary Platform implementation for Linux.

use mycelium_core::error::Result;
use mycelium_core::platform::{
	MemoryPlatform, NetworkPlatform, ProcessPlatform, SecurityPlatform, ServicePlatform,
	StoragePlatform, SystemPlatform, TuningPlatform,
};
use mycelium_core::types::*;

#[cfg(feature = "ebpf")]
use std::sync::Arc;

/// Linux backend using /proc, /sys, nix, and systemd D-Bus.
pub struct LinuxPlatform {
	#[cfg(feature = "ebpf")]
	probe_state: Arc<crate::probe::ProbeState>,
}

impl LinuxPlatform {
	pub fn new() -> Self {
		Self {
			#[cfg(feature = "ebpf")]
			probe_state: Arc::new(crate::probe::ProbeState::new()),
		}
	}
}

impl Default for LinuxPlatform {
	fn default() -> Self {
		Self::new()
	}
}

impl ProcessPlatform for LinuxPlatform {
	fn list_processes(&self) -> Result<Vec<ProcessInfo>> {
		crate::process::list_processes()
	}

	fn inspect_process(&self, pid: u32) -> Result<ProcessInfo> {
		crate::process::inspect_process(pid)
	}

	fn process_resources(&self, pid: u32) -> Result<ProcessResource> {
		crate::process::process_resources(pid)
	}

	fn kill_process(&self, pid: u32, signal: Signal) -> Result<()> {
		crate::process::kill_process(pid, signal)
	}

	fn list_process_threads(&self, pid: u32) -> Result<Vec<ThreadInfo>> {
		crate::process::list_process_threads(pid)
	}

	fn list_process_modules(&self, pid: u32) -> Result<Vec<ProcessModule>> {
		crate::process::list_process_modules(pid)
	}

	fn process_environment(&self, pid: u32) -> Result<Vec<(String, String)>> {
		crate::process::process_environment(pid)
	}

	fn list_process_privileges(&self, pid: u32) -> Result<Vec<PrivilegeInfo>> {
		crate::process::list_process_privileges(pid)
	}

	fn list_process_handles(&self, pid: u32) -> Result<Vec<HandleInfo>> {
		crate::process::list_process_handles(pid)
	}

	fn inspect_process_token(&self, pid: u32) -> Result<TokenInfo> {
		crate::process::inspect_process_token(pid)
	}

	fn inspect_elf(&self, target: &ElfTarget) -> Result<ElfInfo> {
		crate::elf::inspect_elf(target)
	}
}

impl MemoryPlatform for LinuxPlatform {
	fn memory_info(&self) -> Result<MemoryInfo> {
		crate::memory::memory_info()
	}

	fn process_memory(&self, pid: u32) -> Result<ProcessMemory> {
		crate::memory::process_memory(pid)
	}

	fn process_memory_maps(&self, pid: u32) -> Result<Vec<MemoryRegion>> {
		crate::memory::process_memory_maps(pid)
	}

	fn read_process_memory(&self, pid: u32, address: u64, size: usize) -> Result<Vec<u8>> {
		crate::memory::read_process_memory(pid, address, size)
	}

	fn write_process_memory(&self, pid: u32, address: u64, data: &[u8]) -> Result<usize> {
		crate::memory::write_process_memory(pid, address, data)
	}

	fn search_process_memory(
		&self,
		pid: u32,
		pattern: &SearchPattern,
		options: &MemorySearchOptions,
	) -> Result<Vec<MemoryMatch>> {
		crate::memory::search_process_memory(pid, pattern, options)
	}
}

impl NetworkPlatform for LinuxPlatform {
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

	fn add_firewall_rule(&self, rule: &FirewallRule) -> Result<()> {
		crate::network::add_firewall_rule(rule)
	}

	fn remove_firewall_rule(&self, rule_id: &str) -> Result<()> {
		crate::network::remove_firewall_rule(rule_id)
	}
}

impl StoragePlatform for LinuxPlatform {
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
}

impl SystemPlatform for LinuxPlatform {
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
}

impl TuningPlatform for LinuxPlatform {
	fn get_tunable(&self, key: &str) -> Result<TunableValue> {
		crate::tuning::get_tunable(key)
	}

	fn list_tunables(&self, prefix: &str) -> Result<Vec<TunableParam>> {
		crate::tuning::list_tunables(prefix)
	}

	fn set_tunable(&self, key: &str, value: &TunableValue) -> Result<TunableValue> {
		crate::tuning::set_tunable(key, value)
	}
}

impl ServicePlatform for LinuxPlatform {
	fn list_services(&self) -> Result<Vec<ServiceInfo>> {
		crate::service::list_services()
	}

	fn service_status(&self, name: &str) -> Result<ServiceInfo> {
		crate::service::service_status(name)
	}

	fn service_action(&self, name: &str, action: ServiceAction) -> Result<()> {
		crate::service::service_action(name, action)
	}

	fn read_logs(&self, query: &LogQuery) -> Result<Vec<LogEntry>> {
		crate::service::read_logs(query)
	}
}

impl SecurityPlatform for LinuxPlatform {
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

	fn list_persistence_entries(&self) -> Result<Vec<PersistenceEntry>> {
		crate::persistence::list_persistence_entries()
	}

	fn detect_hooks(&self, pid: u32) -> Result<Vec<HookInfo>> {
		crate::hooks::detect_hooks(pid)
	}
}

#[cfg(feature = "ebpf")]
impl mycelium_core::platform::ProbePlatform for LinuxPlatform {
	fn attach_probe(&self, config: &ProbeConfig) -> Result<ProbeHandle> {
		crate::probe::attach_probe(config, &self.probe_state)
	}

	fn detach_probe(&self, handle: ProbeHandle) -> Result<()> {
		crate::probe::detach_probe(handle, &self.probe_state)
	}

	fn list_probes(&self) -> Result<Vec<ProbeInfo>> {
		crate::probe::list_probes(&self.probe_state)
	}

	fn read_probe_events(&self, handle: &ProbeHandle) -> Result<Vec<ProbeEvent>> {
		crate::probe::read_probe_events(handle, &self.probe_state)
	}
}
