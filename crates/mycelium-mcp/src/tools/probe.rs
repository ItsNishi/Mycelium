//! Probe tool handlers for eBPF attach/detach/list/read.

use rmcp::ErrorData as McpError;
use rmcp::model::CallToolResult;

use mycelium_core::types::ProbeType;

use super::response::{dry_run_text, err_text, ok_json, ok_text};
use crate::MyceliumMcpService;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AttachRequest {
	/// Probe type: "syscall-trace" or "network-monitor"
	#[schemars(description = "Probe type: syscall-trace or network-monitor")]
	pub probe_type: String,
	/// Target: PID for syscall-trace, interface name for network-monitor (optional)
	#[schemars(description = "Target: PID for syscall-trace, interface for network-monitor")]
	pub target: Option<String>,
	/// Filter: comma-separated syscall names/numbers or protocol:port list (optional)
	#[schemars(description = "Filter: syscall names/numbers or protocol:port list")]
	pub filter: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct HandleRequest {
	/// Probe handle ID
	#[schemars(description = "Probe handle ID returned by probe_attach")]
	pub handle: u64,
}

pub async fn handle_attach(
	svc: &MyceliumMcpService,
	req: AttachRequest,
) -> Result<CallToolResult, McpError> {
	if let Some(result) = svc.check_policy("probe_attach", None) {
		return result;
	}
	if let Some(result) = svc.check_rate_limit("probe_attach") {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("probe_attach");
	}

	let probe_platform = match svc.probe_platform() {
		Some(p) => p,
		None => return err_text("probes not available (ebpf feature not enabled)"),
	};

	let probe_type = match req.probe_type.as_str() {
		"syscall-trace" => ProbeType::SyscallTrace,
		"network-monitor" => ProbeType::NetworkMonitor,
		other => return err_text(&format!("unknown probe type: {other}")),
	};

	let config = mycelium_core::types::ProbeConfig {
		probe_type,
		target: req.target,
		filter: req.filter,
	};

	match tokio::task::spawn_blocking(move || probe_platform.attach_probe(&config)).await {
		Ok(Ok(handle)) => {
			svc.log_success("probe_attach", None);
			ok_json(&handle)
		}
		Ok(Err(e)) => {
			svc.log_failure("probe_attach", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => svc.handle_join_error("probe_attach", e),
	}
}

pub async fn handle_detach(
	svc: &MyceliumMcpService,
	req: HandleRequest,
) -> Result<CallToolResult, McpError> {
	if let Some(result) = svc.check_policy("probe_detach", None) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("probe_detach");
	}

	let probe_platform = match svc.probe_platform() {
		Some(p) => p,
		None => return err_text("probes not available (ebpf feature not enabled)"),
	};

	let handle = mycelium_core::types::ProbeHandle(req.handle);

	match tokio::task::spawn_blocking(move || probe_platform.detach_probe(handle)).await {
		Ok(Ok(())) => {
			svc.log_success("probe_detach", None);
			ok_text(format!("probe {} detached", req.handle))
		}
		Ok(Err(e)) => {
			svc.log_failure("probe_detach", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => svc.handle_join_error("probe_detach", e),
	}
}

pub async fn handle_list(svc: &MyceliumMcpService) -> Result<CallToolResult, McpError> {
	if let Some(result) = svc.check_policy("probe_list", None) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("probe_list");
	}

	let probe_platform = match svc.probe_platform() {
		Some(p) => p,
		None => return err_text("probes not available (ebpf feature not enabled)"),
	};

	match tokio::task::spawn_blocking(move || probe_platform.list_probes()).await {
		Ok(Ok(probes)) => {
			svc.log_success("probe_list", None);
			ok_json(&probes)
		}
		Ok(Err(e)) => {
			svc.log_failure("probe_list", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => svc.handle_join_error("probe_list", e),
	}
}

pub async fn handle_read(
	svc: &MyceliumMcpService,
	req: HandleRequest,
) -> Result<CallToolResult, McpError> {
	if let Some(result) = svc.check_policy("probe_read", None) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("probe_read");
	}

	let probe_platform = match svc.probe_platform() {
		Some(p) => p,
		None => return err_text("probes not available (ebpf feature not enabled)"),
	};

	let handle = mycelium_core::types::ProbeHandle(req.handle);

	match tokio::task::spawn_blocking(move || probe_platform.read_probe_events(&handle)).await {
		Ok(Ok(events)) => {
			svc.log_success("probe_read", None);
			ok_json(&events)
		}
		Ok(Err(e)) => {
			svc.log_failure("probe_read", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => svc.handle_join_error("probe_read", e),
	}
}
