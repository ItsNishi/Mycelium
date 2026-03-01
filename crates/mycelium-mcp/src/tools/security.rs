//! Security tool handlers.

use rmcp::ErrorData as McpError;
use rmcp::model::CallToolResult;

use super::response::{dry_run_text, err_text, ok_json};
use crate::MyceliumMcpService;

pub async fn handle_users(svc: &MyceliumMcpService) -> Result<CallToolResult, McpError> {
	if let Some(result) = svc.check_policy("security_users", None) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("security_users");
	}

	let platform = svc.platform();
	match tokio::task::spawn_blocking(move || platform.list_users()).await {
		Ok(Ok(users)) => {
			svc.log_success("security_users", None);
			ok_json(&users)
		}
		Ok(Err(e)) => {
			svc.log_failure("security_users", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => err_text(&format!("task join error: {e}")),
	}
}

pub async fn handle_groups(svc: &MyceliumMcpService) -> Result<CallToolResult, McpError> {
	if let Some(result) = svc.check_policy("security_groups", None) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("security_groups");
	}

	let platform = svc.platform();
	match tokio::task::spawn_blocking(move || platform.list_groups()).await {
		Ok(Ok(groups)) => {
			svc.log_success("security_groups", None);
			ok_json(&groups)
		}
		Ok(Err(e)) => {
			svc.log_failure("security_groups", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => err_text(&format!("task join error: {e}")),
	}
}

pub async fn handle_modules(svc: &MyceliumMcpService) -> Result<CallToolResult, McpError> {
	if let Some(result) = svc.check_policy("security_modules", None) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("security_modules");
	}

	let platform = svc.platform();
	match tokio::task::spawn_blocking(move || platform.list_kernel_modules()).await {
		Ok(Ok(modules)) => {
			svc.log_success("security_modules", None);
			ok_json(&modules)
		}
		Ok(Err(e)) => {
			svc.log_failure("security_modules", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => err_text(&format!("task join error: {e}")),
	}
}

pub async fn handle_status(svc: &MyceliumMcpService) -> Result<CallToolResult, McpError> {
	if let Some(result) = svc.check_policy("security_status", None) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("security_status");
	}

	let platform = svc.platform();
	match tokio::task::spawn_blocking(move || platform.security_status()).await {
		Ok(Ok(status)) => {
			svc.log_success("security_status", None);
			ok_json(&status)
		}
		Ok(Err(e)) => {
			svc.log_failure("security_status", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => err_text(&format!("task join error: {e}")),
	}
}
