//! Network tool handlers.

use rmcp::ErrorData as McpError;
use rmcp::model::CallToolResult;

use super::response::{dry_run_text, err_text, mapped_err, ok_json, ok_text};
use crate::MyceliumMcpService;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct FirewallAddRequest {
	/// Chain name (e.g. INPUT, OUTPUT, FORWARD)
	#[schemars(description = "Firewall chain: INPUT, OUTPUT, FORWARD")]
	pub chain: String,
	/// Protocol (tcp, udp, icmp)
	#[schemars(description = "Protocol: tcp, udp, icmp")]
	pub protocol: Option<String>,
	/// Source address/CIDR
	#[schemars(description = "Source address or CIDR")]
	pub source: Option<String>,
	/// Destination address/CIDR
	#[schemars(description = "Destination address or CIDR")]
	pub destination: Option<String>,
	/// Port number
	#[schemars(description = "Port number")]
	pub port: Option<u16>,
	/// Action: accept, drop, reject, log
	#[schemars(description = "Rule action: accept, drop, reject, log")]
	pub action: String,
	/// Optional comment
	#[schemars(description = "Optional comment for the rule")]
	pub comment: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct FirewallRemoveRequest {
	/// Rule ID to remove
	#[schemars(description = "Firewall rule ID to remove")]
	pub rule_id: String,
}

pub async fn handle_interfaces(svc: &MyceliumMcpService) -> Result<CallToolResult, McpError> {
	if let Some(result) = svc.check_policy("network_interfaces", None) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("network_interfaces");
	}

	let platform = svc.platform();
	match tokio::task::spawn_blocking(move || platform.list_interfaces()).await {
		Ok(Ok(ifaces)) => {
			svc.log_success("network_interfaces", None);
			ok_json(&ifaces)
		}
		Ok(Err(e)) => {
			svc.log_failure("network_interfaces", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => svc.handle_join_error("network_interfaces", e),
	}
}

pub async fn handle_connections(svc: &MyceliumMcpService) -> Result<CallToolResult, McpError> {
	if let Some(result) = svc.check_policy("network_connections", None) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("network_connections");
	}

	let platform = svc.platform();
	match tokio::task::spawn_blocking(move || platform.list_connections()).await {
		Ok(Ok(conns)) => {
			svc.log_success("network_connections", None);
			ok_json(&conns)
		}
		Ok(Err(e)) => {
			svc.log_failure("network_connections", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => svc.handle_join_error("network_connections", e),
	}
}

pub async fn handle_routes(svc: &MyceliumMcpService) -> Result<CallToolResult, McpError> {
	if let Some(result) = svc.check_policy("network_routes", None) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("network_routes");
	}

	let platform = svc.platform();
	match tokio::task::spawn_blocking(move || platform.list_routes()).await {
		Ok(Ok(routes)) => {
			svc.log_success("network_routes", None);
			ok_json(&routes)
		}
		Ok(Err(e)) => {
			svc.log_failure("network_routes", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => svc.handle_join_error("network_routes", e),
	}
}

pub async fn handle_ports(svc: &MyceliumMcpService) -> Result<CallToolResult, McpError> {
	if let Some(result) = svc.check_policy("network_ports", None) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("network_ports");
	}

	let platform = svc.platform();
	match tokio::task::spawn_blocking(move || platform.list_open_ports()).await {
		Ok(Ok(ports)) => {
			svc.log_success("network_ports", None);
			ok_json(&ports)
		}
		Ok(Err(e)) => {
			svc.log_failure("network_ports", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => svc.handle_join_error("network_ports", e),
	}
}

pub async fn handle_firewall(svc: &MyceliumMcpService) -> Result<CallToolResult, McpError> {
	if let Some(result) = svc.check_policy("network_firewall", None) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("network_firewall");
	}

	let platform = svc.platform();
	match tokio::task::spawn_blocking(move || platform.list_firewall_rules()).await {
		Ok(Ok(rules)) => {
			svc.log_success("network_firewall", None);
			ok_json(&rules)
		}
		Ok(Err(e)) => {
			svc.log_failure("network_firewall", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => svc.handle_join_error("network_firewall", e),
	}
}

pub async fn handle_firewall_add(svc: &MyceliumMcpService, req: FirewallAddRequest) -> Result<CallToolResult, McpError> {
	use mycelium_core::types::{FirewallAction, FirewallRule};

	let resource = format!("chain:{}", req.chain);
	if let Some(result) = svc.check_policy("firewall_add", Some(&resource)) {
		return result;
	}
	if let Some(result) = svc.check_rate_limit("firewall_add") {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("firewall_add");
	}

	let action = match req.action.to_lowercase().as_str() {
		"accept" => FirewallAction::Accept,
		"drop" => FirewallAction::Drop,
		"reject" => FirewallAction::Reject,
		"log" => FirewallAction::Log,
		other => return err_text(&format!("unknown firewall action: {other}")),
	};

	let rule = FirewallRule {
		id: String::new(),
		chain: req.chain,
		protocol: req.protocol,
		source: req.source,
		destination: req.destination,
		port: req.port,
		action,
		comment: req.comment,
	};

	let platform = svc.platform();
	match tokio::task::spawn_blocking(move || platform.add_firewall_rule(&rule)).await {
		Ok(Ok(())) => {
			svc.log_success("firewall_add", Some(&resource));
			ok_text("firewall rule added")
		}
		Ok(Err(e)) => {
			svc.log_failure("firewall_add", &e.to_string());
			mapped_err(&e, None)
		}
		Err(e) => svc.handle_join_error("firewall_add", e),
	}
}

pub async fn handle_firewall_remove(svc: &MyceliumMcpService, req: FirewallRemoveRequest) -> Result<CallToolResult, McpError> {
	let resource = format!("rule_id:{}", req.rule_id);
	if let Some(result) = svc.check_policy("firewall_remove", Some(&resource)) {
		return result;
	}
	if let Some(result) = svc.check_rate_limit("firewall_remove") {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("firewall_remove");
	}

	let platform = svc.platform();
	let rule_id = req.rule_id.clone();
	match tokio::task::spawn_blocking(move || platform.remove_firewall_rule(&rule_id)).await {
		Ok(Ok(())) => {
			svc.log_success("firewall_remove", Some(&resource));
			ok_text("firewall rule removed")
		}
		Ok(Err(e)) => {
			svc.log_failure("firewall_remove", &e.to_string());
			mapped_err(&e, None)
		}
		Err(e) => svc.handle_join_error("firewall_remove", e),
	}
}
