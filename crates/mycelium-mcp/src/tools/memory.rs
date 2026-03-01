//! Memory tool handlers.

use rmcp::ErrorData as McpError;
use rmcp::model::CallToolResult;

use super::process::PidRequest;
use super::response::{dry_run_text, err_text, ok_json};
use crate::MyceliumMcpService;

pub async fn handle_info(svc: &MyceliumMcpService) -> Result<CallToolResult, McpError> {
	if let Some(result) = svc.check_policy("memory_info", None) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("memory_info");
	}

	let platform = svc.platform();
	match tokio::task::spawn_blocking(move || platform.memory_info()).await {
		Ok(Ok(info)) => {
			svc.log_success("memory_info", None);
			ok_json(&info)
		}
		Ok(Err(e)) => {
			svc.log_failure("memory_info", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => err_text(&format!("task join error: {e}")),
	}
}

pub async fn handle_process(svc: &MyceliumMcpService, req: PidRequest) -> Result<CallToolResult, McpError> {
	let resource = format!("pid:{}", req.pid);
	if let Some(result) = svc.check_policy("memory_process", Some(&resource)) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("memory_process");
	}

	let platform = svc.platform();
	let pid = req.pid;
	match tokio::task::spawn_blocking(move || platform.process_memory(pid)).await {
		Ok(Ok(mem)) => {
			svc.log_success("memory_process", Some(&resource));
			ok_json(&mem)
		}
		Ok(Err(e)) => {
			svc.log_failure("memory_process", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => err_text(&format!("task join error: {e}")),
	}
}
