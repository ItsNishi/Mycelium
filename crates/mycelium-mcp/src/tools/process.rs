//! Process tool handlers.

use rmcp::ErrorData as McpError;
use rmcp::model::CallToolResult;

use super::response::{dry_run_text, err_text, mapped_err, ok_json};
use crate::MyceliumMcpService;
use crate::error_mapping::ErrorContext;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct PidRequest {
	/// Process ID
	#[schemars(description = "Process ID to inspect")]
	pub pid: u32,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct KillRequest {
	/// Process ID to signal
	#[schemars(description = "Process ID to send signal to")]
	pub pid: u32,
	/// Signal name (e.g. TERM, KILL, HUP, INT, USR1, USR2, STOP, CONT)
	#[schemars(description = "Signal name: TERM, KILL, HUP, INT, USR1, USR2, STOP, CONT")]
	pub signal: String,
}

pub async fn handle_list(svc: &MyceliumMcpService) -> Result<CallToolResult, McpError> {
	if let Some(result) = svc.check_policy("process_list", None) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("process_list");
	}

	let platform = svc.platform();
	match tokio::task::spawn_blocking(move || platform.list_processes()).await {
		Ok(Ok(procs)) => {
			svc.log_success("process_list", None);
			ok_json(&procs)
		}
		Ok(Err(e)) => {
			svc.log_failure("process_list", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => svc.handle_join_error("process_list", e),
	}
}

pub async fn handle_inspect(
	svc: &MyceliumMcpService,
	req: PidRequest,
) -> Result<CallToolResult, McpError> {
	use mycelium_core::policy::rule::ResourceContext;

	let resource = format!("pid:{}", req.pid);
	let ctx = ResourceContext {
		pid: Some(req.pid),
		..Default::default()
	};
	if let Some(result) =
		svc.check_policy_with_context("process_inspect", Some(&resource), Some(&ctx))
	{
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("process_inspect");
	}

	let platform = svc.platform();
	let pid = req.pid;
	match tokio::task::spawn_blocking(move || platform.inspect_process(pid)).await {
		Ok(Ok(info)) => {
			svc.log_success("process_inspect", Some(&resource));
			ok_json(&info)
		}
		Ok(Err(e)) => {
			svc.log_failure("process_inspect", &e.to_string());
			mapped_err(&e, Some(&ErrorContext { pid: Some(req.pid) }))
		}
		Err(e) => svc.handle_join_error("process_inspect", e),
	}
}

pub async fn handle_resources(
	svc: &MyceliumMcpService,
	req: PidRequest,
) -> Result<CallToolResult, McpError> {
	use mycelium_core::policy::rule::ResourceContext;

	let resource = format!("pid:{}", req.pid);
	let ctx = ResourceContext {
		pid: Some(req.pid),
		..Default::default()
	};
	if let Some(result) =
		svc.check_policy_with_context("process_resources", Some(&resource), Some(&ctx))
	{
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("process_resources");
	}

	let platform = svc.platform();
	let pid = req.pid;
	match tokio::task::spawn_blocking(move || platform.process_resources(pid)).await {
		Ok(Ok(res)) => {
			svc.log_success("process_resources", Some(&resource));
			ok_json(&res)
		}
		Ok(Err(e)) => {
			svc.log_failure("process_resources", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => svc.handle_join_error("process_resources", e),
	}
}

pub async fn handle_threads(
	svc: &MyceliumMcpService,
	req: PidRequest,
) -> Result<CallToolResult, McpError> {
	use mycelium_core::policy::rule::ResourceContext;

	let resource = format!("pid:{}", req.pid);
	let ctx = ResourceContext {
		pid: Some(req.pid),
		..Default::default()
	};
	if let Some(result) =
		svc.check_policy_with_context("process_threads", Some(&resource), Some(&ctx))
	{
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("process_threads");
	}

	let platform = svc.platform();
	let pid = req.pid;
	match tokio::task::spawn_blocking(move || platform.list_process_threads(pid)).await {
		Ok(Ok(threads)) => {
			svc.log_success("process_threads", Some(&resource));
			ok_json(&threads)
		}
		Ok(Err(e)) => {
			svc.log_failure("process_threads", &e.to_string());
			mapped_err(&e, Some(&ErrorContext { pid: Some(req.pid) }))
		}
		Err(e) => svc.handle_join_error("process_threads", e),
	}
}

pub async fn handle_modules(
	svc: &MyceliumMcpService,
	req: PidRequest,
) -> Result<CallToolResult, McpError> {
	use mycelium_core::policy::rule::ResourceContext;

	let resource = format!("pid:{}", req.pid);
	let ctx = ResourceContext {
		pid: Some(req.pid),
		..Default::default()
	};
	if let Some(result) =
		svc.check_policy_with_context("process_modules", Some(&resource), Some(&ctx))
	{
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("process_modules");
	}

	let platform = svc.platform();
	let pid = req.pid;
	match tokio::task::spawn_blocking(move || platform.list_process_modules(pid)).await {
		Ok(Ok(modules)) => {
			svc.log_success("process_modules", Some(&resource));
			ok_json(&modules)
		}
		Ok(Err(e)) => {
			svc.log_failure("process_modules", &e.to_string());
			mapped_err(&e, Some(&ErrorContext { pid: Some(req.pid) }))
		}
		Err(e) => svc.handle_join_error("process_modules", e),
	}
}

pub async fn handle_environment(
	svc: &MyceliumMcpService,
	req: PidRequest,
) -> Result<CallToolResult, McpError> {
	use mycelium_core::policy::rule::ResourceContext;

	let resource = format!("pid:{}", req.pid);
	let ctx = ResourceContext {
		pid: Some(req.pid),
		..Default::default()
	};
	if let Some(result) =
		svc.check_policy_with_context("process_environment", Some(&resource), Some(&ctx))
	{
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("process_environment");
	}

	let platform = svc.platform();
	let pid = req.pid;
	match tokio::task::spawn_blocking(move || platform.process_environment(pid)).await {
		Ok(Ok(vars)) => {
			svc.log_success("process_environment", Some(&resource));
			// Return as a JSON object
			let map: std::collections::BTreeMap<String, String> = vars.into_iter().collect();
			ok_json(&map)
		}
		Ok(Err(e)) => {
			svc.log_failure("process_environment", &e.to_string());
			mapped_err(&e, Some(&ErrorContext { pid: Some(req.pid) }))
		}
		Err(e) => svc.handle_join_error("process_environment", e),
	}
}

pub async fn handle_privileges(
	svc: &MyceliumMcpService,
	req: PidRequest,
) -> Result<CallToolResult, McpError> {
	use mycelium_core::policy::rule::ResourceContext;

	let resource = format!("pid:{}", req.pid);
	let ctx = ResourceContext {
		pid: Some(req.pid),
		..Default::default()
	};
	if let Some(result) =
		svc.check_policy_with_context("process_privileges", Some(&resource), Some(&ctx))
	{
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("process_privileges");
	}

	let platform = svc.platform();
	let pid = req.pid;
	match tokio::task::spawn_blocking(move || platform.list_process_privileges(pid)).await {
		Ok(Ok(privs)) => {
			svc.log_success("process_privileges", Some(&resource));
			ok_json(&privs)
		}
		Ok(Err(e)) => {
			svc.log_failure("process_privileges", &e.to_string());
			mapped_err(&e, Some(&ErrorContext { pid: Some(req.pid) }))
		}
		Err(e) => svc.handle_join_error("process_privileges", e),
	}
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct PeInspectRequest {
	/// Process ID to inspect (mutually exclusive with path)
	#[schemars(description = "Process ID whose main module PE header to parse")]
	pub pid: Option<u32>,
	/// File path to inspect (mutually exclusive with pid)
	#[schemars(description = "Path to a PE file to parse")]
	pub path: Option<String>,
}

pub async fn handle_handles(
	svc: &MyceliumMcpService,
	req: PidRequest,
) -> Result<CallToolResult, McpError> {
	use mycelium_core::policy::rule::ResourceContext;

	let resource = format!("pid:{}", req.pid);
	let ctx = ResourceContext {
		pid: Some(req.pid),
		..Default::default()
	};
	if let Some(result) =
		svc.check_policy_with_context("process_handles", Some(&resource), Some(&ctx))
	{
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("process_handles");
	}

	let platform = svc.platform();
	let pid = req.pid;
	match tokio::task::spawn_blocking(move || platform.list_process_handles(pid)).await {
		Ok(Ok(handles)) => {
			svc.log_success("process_handles", Some(&resource));
			ok_json(&handles)
		}
		Ok(Err(e)) => {
			svc.log_failure("process_handles", &e.to_string());
			mapped_err(&e, Some(&ErrorContext { pid: Some(req.pid) }))
		}
		Err(e) => svc.handle_join_error("process_handles", e),
	}
}

pub async fn handle_pe_inspect(
	svc: &MyceliumMcpService,
	req: PeInspectRequest,
) -> Result<CallToolResult, McpError> {
	use mycelium_core::types::PeTarget;

	let target = match (req.pid, &req.path) {
		(Some(pid), None) => PeTarget::Pid(pid),
		(None, Some(path)) => PeTarget::Path(path.clone()),
		_ => return err_text("exactly one of 'pid' or 'path' must be provided"),
	};

	let resource = match &target {
		PeTarget::Pid(pid) => format!("pid:{pid}"),
		PeTarget::Path(p) => format!("path:{p}"),
	};

	if let Some(result) = svc.check_policy("process_pe_inspect", Some(&resource)) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("process_pe_inspect");
	}

	let platform = svc.platform();
	match tokio::task::spawn_blocking(move || platform.inspect_pe(&target)).await {
		Ok(Ok(info)) => {
			svc.log_success("process_pe_inspect", Some(&resource));
			ok_json(&info)
		}
		Ok(Err(e)) => {
			svc.log_failure("process_pe_inspect", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => svc.handle_join_error("process_pe_inspect", e),
	}
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ElfInspectRequest {
	/// Process ID to inspect (mutually exclusive with path)
	#[schemars(description = "Process ID whose binary ELF header to parse")]
	pub pid: Option<u32>,
	/// File path to inspect (mutually exclusive with pid)
	#[schemars(description = "Path to an ELF file to parse")]
	pub path: Option<String>,
}

pub async fn handle_elf_inspect(
	svc: &MyceliumMcpService,
	req: ElfInspectRequest,
) -> Result<CallToolResult, McpError> {
	use mycelium_core::types::ElfTarget;

	let target = match (req.pid, &req.path) {
		(Some(pid), None) => ElfTarget::Pid(pid),
		(None, Some(path)) => ElfTarget::Path(path.clone()),
		_ => return err_text("exactly one of 'pid' or 'path' must be provided"),
	};

	let resource = match &target {
		ElfTarget::Pid(pid) => format!("pid:{pid}"),
		ElfTarget::Path(p) => format!("path:{p}"),
	};

	if let Some(result) = svc.check_policy("process_elf_inspect", Some(&resource)) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("process_elf_inspect");
	}

	let platform = svc.platform();
	match tokio::task::spawn_blocking(move || platform.inspect_elf(&target)).await {
		Ok(Ok(info)) => {
			svc.log_success("process_elf_inspect", Some(&resource));
			ok_json(&info)
		}
		Ok(Err(e)) => {
			svc.log_failure("process_elf_inspect", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => svc.handle_join_error("process_elf_inspect", e),
	}
}

pub async fn handle_token(
	svc: &MyceliumMcpService,
	req: PidRequest,
) -> Result<CallToolResult, McpError> {
	use mycelium_core::policy::rule::ResourceContext;

	let resource = format!("pid:{}", req.pid);
	let ctx = ResourceContext {
		pid: Some(req.pid),
		..Default::default()
	};
	if let Some(result) =
		svc.check_policy_with_context("process_token", Some(&resource), Some(&ctx))
	{
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("process_token");
	}

	let platform = svc.platform();
	let pid = req.pid;
	match tokio::task::spawn_blocking(move || platform.inspect_process_token(pid)).await {
		Ok(Ok(info)) => {
			svc.log_success("process_token", Some(&resource));
			ok_json(&info)
		}
		Ok(Err(e)) => {
			svc.log_failure("process_token", &e.to_string());
			mapped_err(&e, Some(&ErrorContext { pid: Some(req.pid) }))
		}
		Err(e) => svc.handle_join_error("process_token", e),
	}
}

pub async fn handle_kill(
	svc: &MyceliumMcpService,
	req: KillRequest,
) -> Result<CallToolResult, McpError> {
	use mycelium_core::policy::rule::ResourceContext;
	use mycelium_core::types::Signal;

	let resource = format!("pid:{}", req.pid);
	let ctx = ResourceContext {
		pid: Some(req.pid),
		..Default::default()
	};
	if let Some(result) = svc.check_policy_with_context("process_kill", Some(&resource), Some(&ctx))
	{
		return result;
	}
	if let Some(result) = svc.check_rate_limit("process_kill") {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("process_kill");
	}

	let signal = match req.signal.to_uppercase().as_str() {
		"TERM" | "SIGTERM" => Signal::Term,
		"KILL" | "SIGKILL" => Signal::Kill,
		"HUP" | "SIGHUP" => Signal::Hup,
		"INT" | "SIGINT" => Signal::Int,
		"USR1" | "SIGUSR1" => Signal::Usr1,
		"USR2" | "SIGUSR2" => Signal::Usr2,
		"STOP" | "SIGSTOP" => Signal::Stop,
		"CONT" | "SIGCONT" => Signal::Cont,
		other => return err_text(&format!("unknown signal: {other}")),
	};

	let platform = svc.platform();
	let pid = req.pid;
	match tokio::task::spawn_blocking(move || platform.kill_process(pid, signal)).await {
		Ok(Ok(())) => {
			svc.log_success("process_kill", Some(&resource));
			super::response::ok_text(format!("signal sent to pid {pid}"))
		}
		Ok(Err(e)) => {
			svc.log_failure("process_kill", &e.to_string());
			mapped_err(&e, Some(&ErrorContext { pid: Some(req.pid) }))
		}
		Err(e) => svc.handle_join_error("process_kill", e),
	}
}
