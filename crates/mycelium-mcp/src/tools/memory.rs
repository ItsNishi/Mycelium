//! Memory tool handlers.

use rmcp::ErrorData as McpError;
use rmcp::model::CallToolResult;

use super::process::PidRequest;
use super::response::{dry_run_text, err_text, ok_json, ok_text};
use crate::MyceliumMcpService;

/// Request for reading raw process memory.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct MemoryReadRequest {
	/// Process ID to read from
	#[schemars(description = "Process ID to read from")]
	pub pid: u32,
	/// Start address in virtual memory
	#[schemars(description = "Start address in process virtual memory")]
	pub address: u64,
	/// Number of bytes to read (max 1 MiB)
	#[schemars(description = "Number of bytes to read (max 1048576)")]
	pub size: u64,
}

/// Request for writing raw process memory.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct MemoryWriteRequest {
	/// Process ID to write to
	#[schemars(description = "Process ID to write to")]
	pub pid: u32,
	/// Start address in virtual memory
	#[schemars(description = "Start address in process virtual memory")]
	pub address: u64,
	/// Hex-encoded bytes to write (e.g. "4141ff00")
	#[schemars(description = "Hex-encoded bytes to write (e.g. \"4141ff00\")")]
	pub hex_data: String,
}

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

pub async fn handle_maps(svc: &MyceliumMcpService, req: PidRequest) -> Result<CallToolResult, McpError> {
	let resource = format!("pid:{}", req.pid);
	if let Some(result) = svc.check_policy("memory_maps", Some(&resource)) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("memory_maps");
	}

	let platform = svc.platform();
	let pid = req.pid;
	match tokio::task::spawn_blocking(move || platform.process_memory_maps(pid)).await {
		Ok(Ok(regions)) => {
			svc.log_success("memory_maps", Some(&resource));
			ok_json(&regions)
		}
		Ok(Err(e)) => {
			svc.log_failure("memory_maps", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => err_text(&format!("task join error: {e}")),
	}
}

pub async fn handle_read(svc: &MyceliumMcpService, req: MemoryReadRequest) -> Result<CallToolResult, McpError> {
	let resource = format!("pid:{}:addr:{:#x}:size:{}", req.pid, req.address, req.size);
	if let Some(result) = svc.check_policy("memory_read", Some(&resource)) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("memory_read");
	}

	let platform = svc.platform();
	let pid = req.pid;
	let address = req.address;
	let size = req.size as usize;
	match tokio::task::spawn_blocking(move || platform.read_process_memory(pid, address, size)).await {
		Ok(Ok(data)) => {
			svc.log_success("memory_read", Some(&resource));
			let hex = data.iter().map(|b| format!("{b:02x}")).collect::<String>();
			ok_text(hex)
		}
		Ok(Err(e)) => {
			svc.log_failure("memory_read", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => err_text(&format!("task join error: {e}")),
	}
}

pub async fn handle_write(svc: &MyceliumMcpService, req: MemoryWriteRequest) -> Result<CallToolResult, McpError> {
	let resource = format!("pid:{}:addr:{:#x}", req.pid, req.address);
	if let Some(result) = svc.check_policy("memory_write", Some(&resource)) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("memory_write");
	}

	let data = match hex_decode(&req.hex_data) {
		Ok(d) => d,
		Err(msg) => return err_text(&msg),
	};

	let platform = svc.platform();
	let pid = req.pid;
	let address = req.address;
	match tokio::task::spawn_blocking(move || platform.write_process_memory(pid, address, &data)).await {
		Ok(Ok(written)) => {
			svc.log_success("memory_write", Some(&resource));
			ok_text(format!("{written} bytes written to pid {pid} at {address:#x}"))
		}
		Ok(Err(e)) => {
			svc.log_failure("memory_write", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => err_text(&format!("task join error: {e}")),
	}
}

/// Decode a hex string (e.g. "4141ff00") into bytes.
fn hex_decode(s: &str) -> std::result::Result<Vec<u8>, String> {
	let s = s.strip_prefix("0x").unwrap_or(s);
	if !s.len().is_multiple_of(2) {
		return Err(format!("hex string has odd length: {}", s.len()));
	}
	(0..s.len())
		.step_by(2)
		.map(|i| {
			u8::from_str_radix(&s[i..i + 2], 16)
				.map_err(|e| format!("invalid hex at position {i}: {e}"))
		})
		.collect()
}
