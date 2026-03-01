//! Storage tool handlers.

use rmcp::ErrorData as McpError;
use rmcp::model::CallToolResult;

use super::response::{dry_run_text, err_text, ok_json};
use crate::MyceliumMcpService;

pub async fn handle_disks(svc: &MyceliumMcpService) -> Result<CallToolResult, McpError> {
	if let Some(result) = svc.check_policy("storage_disks", None) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("storage_disks");
	}

	let platform = svc.platform();
	match tokio::task::spawn_blocking(move || platform.list_disks()).await {
		Ok(Ok(disks)) => {
			svc.log_success("storage_disks", None);
			ok_json(&disks)
		}
		Ok(Err(e)) => {
			svc.log_failure("storage_disks", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => err_text(&format!("task join error: {e}")),
	}
}

pub async fn handle_partitions(svc: &MyceliumMcpService) -> Result<CallToolResult, McpError> {
	if let Some(result) = svc.check_policy("storage_partitions", None) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("storage_partitions");
	}

	let platform = svc.platform();
	match tokio::task::spawn_blocking(move || platform.list_partitions()).await {
		Ok(Ok(parts)) => {
			svc.log_success("storage_partitions", None);
			ok_json(&parts)
		}
		Ok(Err(e)) => {
			svc.log_failure("storage_partitions", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => err_text(&format!("task join error: {e}")),
	}
}

pub async fn handle_mounts(svc: &MyceliumMcpService) -> Result<CallToolResult, McpError> {
	if let Some(result) = svc.check_policy("storage_mounts", None) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("storage_mounts");
	}

	let platform = svc.platform();
	match tokio::task::spawn_blocking(move || platform.list_mounts()).await {
		Ok(Ok(mounts)) => {
			svc.log_success("storage_mounts", None);
			ok_json(&mounts)
		}
		Ok(Err(e)) => {
			svc.log_failure("storage_mounts", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => err_text(&format!("task join error: {e}")),
	}
}

pub async fn handle_io(svc: &MyceliumMcpService) -> Result<CallToolResult, McpError> {
	if let Some(result) = svc.check_policy("storage_io", None) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("storage_io");
	}

	let platform = svc.platform();
	match tokio::task::spawn_blocking(move || platform.io_stats()).await {
		Ok(Ok(stats)) => {
			svc.log_success("storage_io", None);
			ok_json(&stats)
		}
		Ok(Err(e)) => {
			svc.log_failure("storage_io", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => err_text(&format!("task join error: {e}")),
	}
}
