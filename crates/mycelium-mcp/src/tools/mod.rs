//! MCP tool definitions and routing.

pub mod log;
pub mod memory;
pub mod network;
pub mod probe;
pub mod process;
pub mod response;
pub mod security;
pub mod service;
pub mod storage;
pub mod system;
pub mod tuning;

use rmcp::ErrorData as McpError;
use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router};

use crate::MyceliumMcpService;

#[tool_router]
impl MyceliumMcpService {
	pub fn create_tool_router() -> ToolRouter<Self> {
		Self::tool_router()
	}

	// -- Process --

	#[tool(description = "List all running processes")]
	async fn process_list(&self) -> Result<CallToolResult, McpError> {
		process::handle_list(self).await
	}

	#[tool(description = "Get detailed info for a single process by PID")]
	async fn process_inspect(
		&self,
		Parameters(req): Parameters<process::PidRequest>,
	) -> Result<CallToolResult, McpError> {
		process::handle_inspect(self, req).await
	}

	#[tool(description = "Get resource usage (CPU, memory, I/O) for a process")]
	async fn process_resources(
		&self,
		Parameters(req): Parameters<process::PidRequest>,
	) -> Result<CallToolResult, McpError> {
		process::handle_resources(self, req).await
	}

	#[tool(description = "Send a signal to a process (TERM, KILL, HUP, etc.)")]
	async fn process_kill(
		&self,
		Parameters(req): Parameters<process::KillRequest>,
	) -> Result<CallToolResult, McpError> {
		process::handle_kill(self, req).await
	}

	#[tool(description = "List threads belonging to a process by PID")]
	async fn process_threads(
		&self,
		Parameters(req): Parameters<process::PidRequest>,
	) -> Result<CallToolResult, McpError> {
		process::handle_threads(self, req).await
	}

	#[tool(description = "List loaded modules (shared libraries / DLLs) for a process by PID")]
	async fn process_modules(
		&self,
		Parameters(req): Parameters<process::PidRequest>,
	) -> Result<CallToolResult, McpError> {
		process::handle_modules(self, req).await
	}

	#[tool(description = "Get environment variables for a process by PID")]
	async fn process_environment(
		&self,
		Parameters(req): Parameters<process::PidRequest>,
	) -> Result<CallToolResult, McpError> {
		process::handle_environment(self, req).await
	}

	#[tool(description = "List token privileges for a process by PID")]
	async fn process_privileges(
		&self,
		Parameters(req): Parameters<process::PidRequest>,
	) -> Result<CallToolResult, McpError> {
		process::handle_privileges(self, req).await
	}

	#[tool(description = "List open handles (files, registry keys, mutexes, etc.) for a process")]
	async fn process_handles(
		&self,
		Parameters(req): Parameters<process::PidRequest>,
	) -> Result<CallToolResult, McpError> {
		process::handle_handles(self, req).await
	}

	#[tool(
		description = "Parse PE headers of a process or file. Returns imports, exports, sections, characteristics."
	)]
	async fn process_pe_inspect(
		&self,
		Parameters(req): Parameters<process::PeInspectRequest>,
	) -> Result<CallToolResult, McpError> {
		process::handle_pe_inspect(self, req).await
	}

	#[tool(
		description = "Inspect process token security details (integrity, groups, elevation, impersonation)"
	)]
	async fn process_token(
		&self,
		Parameters(req): Parameters<process::PidRequest>,
	) -> Result<CallToolResult, McpError> {
		process::handle_token(self, req).await
	}

	// -- Memory --

	#[tool(description = "Get system-wide memory and swap information")]
	async fn memory_info(&self) -> Result<CallToolResult, McpError> {
		memory::handle_info(self).await
	}

	#[tool(description = "Get memory details for a single process")]
	async fn memory_process(
		&self,
		Parameters(req): Parameters<process::PidRequest>,
	) -> Result<CallToolResult, McpError> {
		memory::handle_process(self, req).await
	}

	#[tool(description = "List memory regions (maps) for a process")]
	async fn memory_maps(
		&self,
		Parameters(req): Parameters<process::PidRequest>,
	) -> Result<CallToolResult, McpError> {
		memory::handle_maps(self, req).await
	}

	#[tool(description = "Read raw bytes from a process's virtual memory")]
	async fn memory_read(
		&self,
		Parameters(req): Parameters<memory::MemoryReadRequest>,
	) -> Result<CallToolResult, McpError> {
		memory::handle_read(self, req).await
	}

	#[tool(description = "Write raw bytes to a process's virtual memory")]
	async fn memory_write(
		&self,
		Parameters(req): Parameters<memory::MemoryWriteRequest>,
	) -> Result<CallToolResult, McpError> {
		memory::handle_write(self, req).await
	}

	#[tool(description = "Search process memory for byte patterns, UTF-8 or UTF-16 strings")]
	async fn memory_search(
		&self,
		Parameters(req): Parameters<memory::MemorySearchRequest>,
	) -> Result<CallToolResult, McpError> {
		memory::handle_search(self, req).await
	}

	// -- Network --

	#[tool(description = "List network interfaces with addresses and stats")]
	async fn network_interfaces(&self) -> Result<CallToolResult, McpError> {
		network::handle_interfaces(self).await
	}

	#[tool(description = "List active network connections")]
	async fn network_connections(&self) -> Result<CallToolResult, McpError> {
		network::handle_connections(self).await
	}

	#[tool(description = "List routing table entries")]
	async fn network_routes(&self) -> Result<CallToolResult, McpError> {
		network::handle_routes(self).await
	}

	#[tool(description = "List open (listening) ports")]
	async fn network_ports(&self) -> Result<CallToolResult, McpError> {
		network::handle_ports(self).await
	}

	#[tool(description = "List firewall rules")]
	async fn network_firewall(&self) -> Result<CallToolResult, McpError> {
		network::handle_firewall(self).await
	}

	#[tool(description = "Add a firewall rule")]
	async fn firewall_add(
		&self,
		Parameters(req): Parameters<network::FirewallAddRequest>,
	) -> Result<CallToolResult, McpError> {
		network::handle_firewall_add(self, req).await
	}

	#[tool(description = "Remove a firewall rule by ID")]
	async fn firewall_remove(
		&self,
		Parameters(req): Parameters<network::FirewallRemoveRequest>,
	) -> Result<CallToolResult, McpError> {
		network::handle_firewall_remove(self, req).await
	}

	// -- Storage --

	#[tool(description = "List physical disks")]
	async fn storage_disks(&self) -> Result<CallToolResult, McpError> {
		storage::handle_disks(self).await
	}

	#[tool(description = "List disk partitions")]
	async fn storage_partitions(&self) -> Result<CallToolResult, McpError> {
		storage::handle_partitions(self).await
	}

	#[tool(description = "List mounted filesystems with usage")]
	async fn storage_mounts(&self) -> Result<CallToolResult, McpError> {
		storage::handle_mounts(self).await
	}

	#[tool(description = "Get I/O statistics per block device")]
	async fn storage_io(&self) -> Result<CallToolResult, McpError> {
		storage::handle_io(self).await
	}

	// -- System --

	#[tool(description = "Get high-level system information (hostname, OS, arch)")]
	async fn system_info(&self) -> Result<CallToolResult, McpError> {
		system::handle_info(self).await
	}

	#[tool(description = "Get kernel version and build info")]
	async fn system_kernel(&self) -> Result<CallToolResult, McpError> {
		system::handle_kernel(self).await
	}

	#[tool(description = "Get CPU model, cores, frequency, and load")]
	async fn system_cpu(&self) -> Result<CallToolResult, McpError> {
		system::handle_cpu(self).await
	}

	#[tool(description = "Get system uptime in seconds")]
	async fn system_uptime(&self) -> Result<CallToolResult, McpError> {
		system::handle_uptime(self).await
	}

	// -- Tuning --

	#[tool(description = "Read a kernel tunable (sysctl) value")]
	async fn tuning_get(
		&self,
		Parameters(req): Parameters<tuning::KeyRequest>,
	) -> Result<CallToolResult, McpError> {
		tuning::handle_get(self, req).await
	}

	#[tool(description = "List kernel tunables matching a prefix")]
	async fn tuning_list(
		&self,
		Parameters(req): Parameters<tuning::PrefixRequest>,
	) -> Result<CallToolResult, McpError> {
		tuning::handle_list(self, req).await
	}

	#[tool(description = "Set a kernel tunable (sysctl) value")]
	async fn tuning_set(
		&self,
		Parameters(req): Parameters<tuning::SetRequest>,
	) -> Result<CallToolResult, McpError> {
		tuning::handle_set(self, req).await
	}

	// -- Services --

	#[tool(description = "List all system services")]
	async fn service_list(&self) -> Result<CallToolResult, McpError> {
		service::handle_list(self).await
	}

	#[tool(description = "Get status of a single service")]
	async fn service_status(
		&self,
		Parameters(req): Parameters<service::NameRequest>,
	) -> Result<CallToolResult, McpError> {
		service::handle_status(self, req).await
	}

	#[tool(description = "Perform an action on a service (start, stop, restart, etc.)")]
	async fn service_action(
		&self,
		Parameters(req): Parameters<service::ActionRequest>,
	) -> Result<CallToolResult, McpError> {
		service::handle_action(self, req).await
	}

	// -- Logs --

	#[tool(description = "Read system log entries with optional filters")]
	async fn log_read(
		&self,
		Parameters(req): Parameters<log::LogReadRequest>,
	) -> Result<CallToolResult, McpError> {
		log::handle_read(self, req).await
	}

	// -- Security --

	#[tool(description = "List system user accounts")]
	async fn security_users(&self) -> Result<CallToolResult, McpError> {
		security::handle_users(self).await
	}

	#[tool(description = "List system groups")]
	async fn security_groups(&self) -> Result<CallToolResult, McpError> {
		security::handle_groups(self).await
	}

	#[tool(description = "List loaded kernel modules")]
	async fn security_modules(&self) -> Result<CallToolResult, McpError> {
		security::handle_modules(self).await
	}

	#[tool(description = "Get security status (SELinux, AppArmor, firewall, SSH config)")]
	async fn security_status(&self) -> Result<CallToolResult, McpError> {
		security::handle_status(self).await
	}

	#[tool(
		description = "Scan persistence mechanisms (Linux: cron, systemd timers, init scripts, XDG autostart, shell profiles, udev; Windows: registry, services, tasks, startup, WMI, COM)"
	)]
	async fn security_persistence(&self) -> Result<CallToolResult, McpError> {
		security::handle_persistence(self).await
	}

	#[tool(
		description = "Detect hooks in a process (Linux: LD_PRELOAD, suspicious libraries, ptrace; Windows: inline, IAT, EAT)"
	)]
	async fn security_detect_hooks(
		&self,
		Parameters(req): Parameters<security::DetectHooksRequest>,
	) -> Result<CallToolResult, McpError> {
		security::handle_detect_hooks(self, req).await
	}

	// -- Probes --

	#[tool(
		description = "Attach an eBPF probe (syscall-trace or network-monitor). Requires CAP_BPF/root."
	)]
	async fn probe_attach(
		&self,
		Parameters(req): Parameters<probe::AttachRequest>,
	) -> Result<CallToolResult, McpError> {
		probe::handle_attach(self, req).await
	}

	#[tool(description = "Detach a running eBPF probe by handle")]
	async fn probe_detach(
		&self,
		Parameters(req): Parameters<probe::HandleRequest>,
	) -> Result<CallToolResult, McpError> {
		probe::handle_detach(self, req).await
	}

	#[tool(description = "List all active eBPF probes")]
	async fn probe_list(&self) -> Result<CallToolResult, McpError> {
		probe::handle_list(self).await
	}

	#[tool(description = "Read events from an active eBPF probe")]
	async fn probe_read(
		&self,
		Parameters(req): Parameters<probe::HandleRequest>,
	) -> Result<CallToolResult, McpError> {
		probe::handle_read(self, req).await
	}
}
