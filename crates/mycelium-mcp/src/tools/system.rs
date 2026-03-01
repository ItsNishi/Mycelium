//! System tool handlers.

use rmcp::ErrorData as McpError;
use rmcp::model::CallToolResult;

use super::response::{dry_run_text, err_text, ok_json, ok_text};
use crate::MyceliumMcpService;

pub async fn handle_info(svc: &MyceliumMcpService) -> Result<CallToolResult, McpError> {
	if let Some(result) = svc.check_policy("system_info", None) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("system_info");
	}

	let platform = svc.platform();
	match tokio::task::spawn_blocking(move || platform.system_info()).await {
		Ok(Ok(info)) => {
			svc.log_success("system_info", None);
			ok_json(&info)
		}
		Ok(Err(e)) => {
			svc.log_failure("system_info", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => err_text(&format!("task join error: {e}")),
	}
}

pub async fn handle_kernel(svc: &MyceliumMcpService) -> Result<CallToolResult, McpError> {
	if let Some(result) = svc.check_policy("system_kernel", None) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("system_kernel");
	}

	let platform = svc.platform();
	match tokio::task::spawn_blocking(move || platform.kernel_info()).await {
		Ok(Ok(info)) => {
			svc.log_success("system_kernel", None);
			ok_json(&info)
		}
		Ok(Err(e)) => {
			svc.log_failure("system_kernel", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => err_text(&format!("task join error: {e}")),
	}
}

pub async fn handle_cpu(svc: &MyceliumMcpService) -> Result<CallToolResult, McpError> {
	if let Some(result) = svc.check_policy("system_cpu", None) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("system_cpu");
	}

	let platform = svc.platform();
	match tokio::task::spawn_blocking(move || platform.cpu_info()).await {
		Ok(Ok(info)) => {
			svc.log_success("system_cpu", None);
			ok_json(&info)
		}
		Ok(Err(e)) => {
			svc.log_failure("system_cpu", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => err_text(&format!("task join error: {e}")),
	}
}

pub async fn handle_uptime(svc: &MyceliumMcpService) -> Result<CallToolResult, McpError> {
	if let Some(result) = svc.check_policy("system_uptime", None) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("system_uptime");
	}

	let platform = svc.platform();
	match tokio::task::spawn_blocking(move || platform.uptime()).await {
		Ok(Ok(secs)) => {
			svc.log_success("system_uptime", None);
			ok_text(format!("{secs}"))
		}
		Ok(Err(e)) => {
			svc.log_failure("system_uptime", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => err_text(&format!("task join error: {e}")),
	}
}
