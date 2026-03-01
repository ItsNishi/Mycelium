//! Tuning tool handlers.

use rmcp::ErrorData as McpError;
use rmcp::model::CallToolResult;

use super::response::{dry_run_text, err_text, ok_json, ok_text};
use crate::MyceliumMcpService;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct KeyRequest {
	/// Sysctl key to read
	#[schemars(description = "Sysctl key (e.g. net.ipv4.ip_forward)")]
	pub key: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct PrefixRequest {
	/// Sysctl key prefix to list
	#[schemars(description = "Sysctl key prefix (e.g. net.ipv4)")]
	pub prefix: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct SetRequest {
	/// Sysctl key to set
	#[schemars(description = "Sysctl key to set")]
	pub key: String,
	/// New value
	#[schemars(description = "New value for the tunable")]
	pub value: String,
}

pub async fn handle_get(svc: &MyceliumMcpService, req: KeyRequest) -> Result<CallToolResult, McpError> {
	let resource = format!("key:{}", req.key);
	if let Some(result) = svc.check_policy("tuning_get", Some(&resource)) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("tuning_get");
	}

	let platform = svc.platform();
	let key = req.key.clone();
	match tokio::task::spawn_blocking(move || platform.get_tunable(&key)).await {
		Ok(Ok(val)) => {
			svc.log_success("tuning_get", Some(&resource));
			ok_json(&val)
		}
		Ok(Err(e)) => {
			svc.log_failure("tuning_get", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => err_text(&format!("task join error: {e}")),
	}
}

pub async fn handle_list(svc: &MyceliumMcpService, req: PrefixRequest) -> Result<CallToolResult, McpError> {
	let resource = format!("prefix:{}", req.prefix);
	if let Some(result) = svc.check_policy("tuning_list", Some(&resource)) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("tuning_list");
	}

	let platform = svc.platform();
	let prefix = req.prefix.clone();
	match tokio::task::spawn_blocking(move || platform.list_tunables(&prefix)).await {
		Ok(Ok(params)) => {
			svc.log_success("tuning_list", Some(&resource));
			ok_json(&params)
		}
		Ok(Err(e)) => {
			svc.log_failure("tuning_list", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => err_text(&format!("task join error: {e}")),
	}
}

pub async fn handle_set(svc: &MyceliumMcpService, req: SetRequest) -> Result<CallToolResult, McpError> {
	use mycelium_core::types::TunableValue;

	let resource = format!("key:{}", req.key);
	if let Some(result) = svc.check_policy("tuning_set", Some(&resource)) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("tuning_set");
	}

	// Try to parse as integer, then boolean, then string
	let value = if let Ok(n) = req.value.parse::<i64>() {
		TunableValue::Integer(n)
	} else if req.value == "true" || req.value == "1" {
		TunableValue::Boolean(true)
	} else if req.value == "false" || req.value == "0" {
		TunableValue::Boolean(false)
	} else {
		TunableValue::String(req.value.clone())
	};

	let platform = svc.platform();
	let key = req.key.clone();
	match tokio::task::spawn_blocking(move || platform.set_tunable(&key, &value)).await {
		Ok(Ok(prev)) => {
			svc.log_success("tuning_set", Some(&resource));
			ok_text(format!("set {} (previous: {})", req.key, prev))
		}
		Ok(Err(e)) => {
			svc.log_failure("tuning_set", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => err_text(&format!("task join error: {e}")),
	}
}
