//! Service tool handlers.

use rmcp::ErrorData as McpError;
use rmcp::model::CallToolResult;

use super::response::{dry_run_text, err_text, mapped_err, ok_json, ok_text};
use crate::MyceliumMcpService;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct NameRequest {
	/// Service name
	#[schemars(description = "Service unit name (e.g. nginx, sshd)")]
	pub name: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ActionRequest {
	/// Service name
	#[schemars(description = "Service unit name")]
	pub name: String,
	/// Action: start, stop, restart, reload, enable, disable
	#[schemars(description = "Action: start, stop, restart, reload, enable, disable")]
	pub action: String,
}

pub async fn handle_list(svc: &MyceliumMcpService) -> Result<CallToolResult, McpError> {
	if let Some(result) = svc.check_policy("service_list", None) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("service_list");
	}

	let platform = svc.platform();
	match tokio::task::spawn_blocking(move || platform.list_services()).await {
		Ok(Ok(services)) => {
			svc.log_success("service_list", None);
			ok_json(&services)
		}
		Ok(Err(e)) => {
			svc.log_failure("service_list", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => svc.handle_join_error("service_list", e),
	}
}

pub async fn handle_status(svc: &MyceliumMcpService, req: NameRequest) -> Result<CallToolResult, McpError> {
	use mycelium_core::policy::rule::ResourceContext;

	let resource = format!("service:{}", req.name);
	let ctx = ResourceContext {
		service_name: Some(req.name.clone()),
		..Default::default()
	};
	if let Some(result) = svc.check_policy_with_context("service_status", Some(&resource), Some(&ctx)) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("service_status");
	}

	let platform = svc.platform();
	let name = req.name.clone();
	match tokio::task::spawn_blocking(move || platform.service_status(&name)).await {
		Ok(Ok(info)) => {
			svc.log_success("service_status", Some(&resource));
			ok_json(&info)
		}
		Ok(Err(e)) => {
			svc.log_failure("service_status", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => svc.handle_join_error("service_status", e),
	}
}

pub async fn handle_action(svc: &MyceliumMcpService, req: ActionRequest) -> Result<CallToolResult, McpError> {
	use mycelium_core::policy::rule::ResourceContext;
	use mycelium_core::types::ServiceAction;

	let resource = format!("service:{}", req.name);
	let ctx = ResourceContext {
		service_name: Some(req.name.clone()),
		..Default::default()
	};
	if let Some(result) = svc.check_policy_with_context("service_action", Some(&resource), Some(&ctx)) {
		return result;
	}
	if let Some(result) = svc.check_rate_limit("service_action") {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("service_action");
	}

	let action = match req.action.to_lowercase().as_str() {
		"start" => ServiceAction::Start,
		"stop" => ServiceAction::Stop,
		"restart" => ServiceAction::Restart,
		"reload" => ServiceAction::Reload,
		"enable" => ServiceAction::Enable,
		"disable" => ServiceAction::Disable,
		other => return err_text(&format!("unknown service action: {other}")),
	};

	let platform = svc.platform();
	let name = req.name.clone();
	match tokio::task::spawn_blocking(move || platform.service_action(&name, action)).await {
		Ok(Ok(())) => {
			svc.log_success("service_action", Some(&resource));
			ok_text(format!("{} {}", req.action, req.name))
		}
		Ok(Err(e)) => {
			svc.log_failure("service_action", &e.to_string());
			mapped_err(&e, None)
		}
		Err(e) => svc.handle_join_error("service_action", e),
	}
}
