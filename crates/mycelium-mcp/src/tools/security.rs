//! Security tool handlers.

use rmcp::ErrorData as McpError;
use rmcp::model::CallToolResult;

use super::response::{dry_run_text, err_text, ok_json};
use crate::MyceliumMcpService;
use crate::error_mapping::ErrorContext;
use super::response::mapped_err;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct DetectHooksRequest {
	/// Process ID to scan for hooks
	#[schemars(description = "Process ID to scan for API hooks")]
	pub pid: u32,
}

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
		Err(e) => svc.handle_join_error("security_users", e),
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
		Err(e) => svc.handle_join_error("security_groups", e),
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
		Err(e) => svc.handle_join_error("security_modules", e),
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
		Err(e) => svc.handle_join_error("security_status", e),
	}
}

pub async fn handle_persistence(svc: &MyceliumMcpService) -> Result<CallToolResult, McpError> {
	if let Some(result) = svc.check_policy("security_persistence", None) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("security_persistence");
	}

	let platform = svc.platform();
	match tokio::task::spawn_blocking(move || platform.list_persistence_entries()).await {
		Ok(Ok(entries)) => {
			svc.log_success("security_persistence", None);
			ok_json(&entries)
		}
		Ok(Err(e)) => {
			svc.log_failure("security_persistence", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => svc.handle_join_error("security_persistence", e),
	}
}

pub async fn handle_detect_hooks(svc: &MyceliumMcpService, req: DetectHooksRequest) -> Result<CallToolResult, McpError> {
	use mycelium_core::policy::rule::ResourceContext;

	let resource = format!("pid:{}", req.pid);
	let ctx = ResourceContext {
		pid: Some(req.pid),
		..Default::default()
	};
	if let Some(result) = svc.check_policy_with_context("security_detect_hooks", Some(&resource), Some(&ctx)) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("security_detect_hooks");
	}

	let platform = svc.platform();
	let pid = req.pid;
	match tokio::task::spawn_blocking(move || platform.detect_hooks(pid)).await {
		Ok(Ok(hooks)) => {
			svc.log_success("security_detect_hooks", Some(&resource));
			ok_json(&hooks)
		}
		Ok(Err(e)) => {
			svc.log_failure("security_detect_hooks", &e.to_string());
			mapped_err(&e, Some(&ErrorContext { pid: Some(req.pid) }))
		}
		Err(e) => svc.handle_join_error("security_detect_hooks", e),
	}
}
