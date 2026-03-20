//! Memory tool handlers.

use rmcp::ErrorData as McpError;
use rmcp::model::CallToolResult;

use super::process::PidRequest;
use super::response::{dry_run_text, err_text, mapped_err, ok_json, ok_text};
use crate::MyceliumMcpService;
use crate::error_mapping::ErrorContext;

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
		Err(e) => svc.handle_join_error("memory_info", e),
	}
}

pub async fn handle_process(
	svc: &MyceliumMcpService,
	req: PidRequest,
) -> Result<CallToolResult, McpError> {
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
		Err(e) => svc.handle_join_error("memory_process", e),
	}
}

pub async fn handle_maps(
	svc: &MyceliumMcpService,
	req: PidRequest,
) -> Result<CallToolResult, McpError> {
	use mycelium_core::policy::rule::ResourceContext;

	let resource = format!("pid:{}", req.pid);
	let ctx = ResourceContext {
		pid: Some(req.pid),
		..Default::default()
	};
	if let Some(result) = svc.check_policy_with_context("memory_maps", Some(&resource), Some(&ctx))
	{
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
		Err(e) => svc.handle_join_error("memory_maps", e),
	}
}

pub async fn handle_read(
	svc: &MyceliumMcpService,
	req: MemoryReadRequest,
) -> Result<CallToolResult, McpError> {
	use mycelium_core::policy::rule::ResourceContext;

	let resource = format!("pid:{}:addr:{:#x}:size:{}", req.pid, req.address, req.size);
	let ctx = ResourceContext {
		pid: Some(req.pid),
		..Default::default()
	};
	if let Some(result) = svc.check_policy_with_context("memory_read", Some(&resource), Some(&ctx))
	{
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("memory_read");
	}

	let platform = svc.platform();
	let pid = req.pid;
	let address = req.address;
	let size = req.size as usize;
	match tokio::task::spawn_blocking(move || platform.read_process_memory(pid, address, size))
		.await
	{
		Ok(Ok(data)) => {
			svc.log_success("memory_read", Some(&resource));
			let hex = data.iter().map(|b| format!("{b:02x}")).collect::<String>();
			ok_text(hex)
		}
		Ok(Err(e)) => {
			svc.log_failure("memory_read", &e.to_string());
			mapped_err(&e, Some(&ErrorContext { pid: Some(req.pid) }))
		}
		Err(e) => svc.handle_join_error("memory_read", e),
	}
}

pub async fn handle_write(
	svc: &MyceliumMcpService,
	req: MemoryWriteRequest,
) -> Result<CallToolResult, McpError> {
	use mycelium_core::policy::rule::ResourceContext;

	let resource = format!("pid:{}:addr:{:#x}", req.pid, req.address);
	let ctx = ResourceContext {
		pid: Some(req.pid),
		..Default::default()
	};
	if let Some(result) = svc.check_policy_with_context("memory_write", Some(&resource), Some(&ctx))
	{
		return result;
	}
	if let Some(result) = svc.check_rate_limit("memory_write") {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("memory_write");
	}

	let data = match hex_decode_masked(&req.hex_data) {
		Ok((d, _)) => d,
		Err(msg) => return err_text(&msg),
	};

	let platform = svc.platform();
	let pid = req.pid;
	let address = req.address;
	match tokio::task::spawn_blocking(move || platform.write_process_memory(pid, address, &data))
		.await
	{
		Ok(Ok(written)) => {
			svc.log_success("memory_write", Some(&resource));
			ok_text(format!(
				"{written} bytes written to pid {pid} at {address:#x}"
			))
		}
		Ok(Err(e)) => {
			svc.log_failure("memory_write", &e.to_string());
			mapped_err(&e, Some(&ErrorContext { pid: Some(req.pid) }))
		}
		Err(e) => svc.handle_join_error("memory_write", e),
	}
}

/// Request for searching process memory for byte patterns or strings.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct MemorySearchRequest {
	/// Process ID to search
	#[schemars(description = "Process ID to search")]
	pub pid: u32,
	/// Hex-encoded byte pattern, supports ?? wildcards (e.g. "4d5a??00", "488B????8905")
	#[schemars(
		description = "Hex-encoded byte pattern to search for. Use ?? for wildcard bytes (e.g. \"488B????8905\")"
	)]
	pub hex_pattern: Option<String>,
	/// UTF-8 string to search for
	#[schemars(description = "UTF-8 string to search for")]
	pub utf8_pattern: Option<String>,
	/// UTF-16 string to search for
	#[schemars(description = "UTF-16LE string to search for")]
	pub utf16_pattern: Option<String>,
	/// Max results (default 100, max 10000)
	#[schemars(description = "Maximum number of matches to return (default 100, max 10000)")]
	pub max_matches: Option<u64>,
	/// Context bytes around each match (default 32, max 256)
	#[schemars(description = "Bytes of context around each match (default 32, max 256)")]
	pub context_size: Option<u64>,
	/// Permission filter (e.g. "rw" for writable regions only)
	#[schemars(description = "Permission filter, e.g. \"rw\" for read+write regions only")]
	pub permissions_filter: Option<String>,
}

pub async fn handle_search(
	svc: &MyceliumMcpService,
	req: MemorySearchRequest,
) -> Result<CallToolResult, McpError> {
	use mycelium_core::policy::rule::ResourceContext;
	use mycelium_core::types::{MemorySearchOptions, SearchPattern};

	let resource = format!("pid:{}", req.pid);
	let ctx = ResourceContext {
		pid: Some(req.pid),
		..Default::default()
	};
	if let Some(result) =
		svc.check_policy_with_context("memory_search", Some(&resource), Some(&ctx))
	{
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("memory_search");
	}

	// Exactly one pattern type must be provided
	let pattern_count = req.hex_pattern.is_some() as u8
		+ req.utf8_pattern.is_some() as u8
		+ req.utf16_pattern.is_some() as u8;
	if pattern_count != 1 {
		return err_text(
			"exactly one of hex_pattern, utf8_pattern, or utf16_pattern must be provided",
		);
	}

	let pattern = if let Some(hex) = &req.hex_pattern {
		match hex_decode_masked(hex) {
			Ok((bytes, None)) => SearchPattern::Bytes(bytes),
			Ok((pattern, Some(mask))) => SearchPattern::MaskedBytes { pattern, mask },
			Err(msg) => return err_text(&msg),
		}
	} else if let Some(utf8) = &req.utf8_pattern {
		SearchPattern::Utf8(utf8.clone())
	} else if let Some(utf16) = &req.utf16_pattern {
		SearchPattern::Utf16(utf16.clone())
	} else {
		unreachable!()
	};

	let options = MemorySearchOptions {
		max_matches: req.max_matches.map(|m| m as usize).unwrap_or(100),
		context_size: req.context_size.map(|c| c as usize).unwrap_or(32),
		permissions_filter: req.permissions_filter.unwrap_or_default(),
	};

	let platform = svc.platform();
	let pid = req.pid;
	match tokio::task::spawn_blocking(move || {
		platform.search_process_memory(pid, &pattern, &options)
	})
	.await
	{
		Ok(Ok(matches)) => {
			svc.log_success("memory_search", Some(&resource));
			ok_json(&matches)
		}
		Ok(Err(e)) => {
			svc.log_failure("memory_search", &e.to_string());
			mapped_err(&e, Some(&ErrorContext { pid: Some(req.pid) }))
		}
		Err(e) => svc.handle_join_error("memory_search", e),
	}
}

/// Decode a hex string that may contain `??` wildcard bytes.
///
/// Returns `(bytes, mask)`. If no wildcards are present, mask is `None`.
/// Wildcard bytes get mask `0x00`, concrete bytes get mask `0xFF`.
fn hex_decode_masked(s: &str) -> std::result::Result<(Vec<u8>, Option<Vec<u8>>), String> {
	let s = s
		.strip_prefix("0x")
		.or_else(|| s.strip_prefix("0X"))
		.unwrap_or(s);
	if !s.len().is_multiple_of(2) {
		return Err(format!("hex string has odd length: {}", s.len()));
	}

	let mut bytes = Vec::with_capacity(s.len() / 2);
	let mut mask = Vec::with_capacity(s.len() / 2);
	let mut has_wildcards = false;

	for i in (0..s.len()).step_by(2) {
		let pair = &s[i..i + 2];
		if pair == "??" {
			bytes.push(0x00);
			mask.push(0x00);
			has_wildcards = true;
		} else {
			let byte = u8::from_str_radix(pair, 16)
				.map_err(|e| format!("invalid hex at position {i}: {e}"))?;
			bytes.push(byte);
			mask.push(0xFF);
		}
	}

	if has_wildcards {
		Ok((bytes, Some(mask)))
	} else {
		Ok((bytes, None))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_hex_decode_masked_normal() {
		let (bytes, mask) = hex_decode_masked("4141ff00").unwrap();
		assert_eq!(bytes, vec![0x41, 0x41, 0xff, 0x00]);
		assert!(mask.is_none());
	}

	#[test]
	fn test_hex_decode_masked_0x_prefix() {
		let (bytes, mask) = hex_decode_masked("0x4141").unwrap();
		assert_eq!(bytes, vec![0x41, 0x41]);
		assert!(mask.is_none());
	}

	#[test]
	fn test_hex_decode_masked_with_wildcards() {
		let (bytes, mask) = hex_decode_masked("48??8B??").unwrap();
		assert_eq!(bytes, vec![0x48, 0x00, 0x8B, 0x00]);
		assert_eq!(mask.unwrap(), vec![0xFF, 0x00, 0xFF, 0x00]);
	}

	#[test]
	fn test_hex_decode_masked_all_wildcards() {
		let (bytes, mask) = hex_decode_masked("??????").unwrap();
		assert_eq!(bytes, vec![0x00, 0x00, 0x00]);
		assert_eq!(mask.unwrap(), vec![0x00, 0x00, 0x00]);
	}

	#[test]
	fn test_hex_decode_masked_odd_length() {
		assert!(hex_decode_masked("414").is_err());
	}

	#[test]
	fn test_hex_decode_masked_invalid_chars() {
		assert!(hex_decode_masked("gg00").is_err());
	}
}
