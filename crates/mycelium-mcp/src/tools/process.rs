//! Process tool handlers.

use rmcp::ErrorData as McpError;
use rmcp::model::CallToolResult;

use super::response::{dry_run_text, err_text, ok_json};
use crate::MyceliumMcpService;

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
		Err(e) => err_text(&format!("task join error: {e}")),
	}
}

pub async fn handle_inspect(svc: &MyceliumMcpService, req: PidRequest) -> Result<CallToolResult, McpError> {
	use mycelium_core::policy::rule::ResourceContext;

	let resource = format!("pid:{}", req.pid);
	let ctx = ResourceContext {
		pid: Some(req.pid),
		..Default::default()
	};
	if let Some(result) = svc.check_policy_with_context("process_inspect", Some(&resource), Some(&ctx)) {
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
			err_text(&e.to_string())
		}
		Err(e) => err_text(&format!("task join error: {e}")),
	}
}

pub async fn handle_resources(svc: &MyceliumMcpService, req: PidRequest) -> Result<CallToolResult, McpError> {
	use mycelium_core::policy::rule::ResourceContext;

	let resource = format!("pid:{}", req.pid);
	let ctx = ResourceContext {
		pid: Some(req.pid),
		..Default::default()
	};
	if let Some(result) = svc.check_policy_with_context("process_resources", Some(&resource), Some(&ctx)) {
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
		Err(e) => err_text(&format!("task join error: {e}")),
	}
}

pub async fn handle_kill(svc: &MyceliumMcpService, req: KillRequest) -> Result<CallToolResult, McpError> {
	use mycelium_core::policy::rule::ResourceContext;
	use mycelium_core::types::Signal;

	let resource = format!("pid:{}", req.pid);
	let ctx = ResourceContext {
		pid: Some(req.pid),
		..Default::default()
	};
	if let Some(result) = svc.check_policy_with_context("process_kill", Some(&resource), Some(&ctx)) {
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
			err_text(&e.to_string())
		}
		Err(e) => err_text(&format!("task join error: {e}")),
	}
}
