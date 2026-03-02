//! Response helpers for MCP tool handlers.

use rmcp::model::{CallToolResult, Content};
use rmcp::ErrorData as McpError;

use crate::error_mapping::{ErrorContext, map_error_message};
use mycelium_core::error::MyceliumError;

/// Return a successful JSON response.
pub fn ok_json<T: serde::Serialize>(value: &T) -> Result<CallToolResult, McpError> {
	match serde_json::to_string_pretty(value) {
		Ok(json) => Ok(CallToolResult::success(vec![Content::text(json)])),
		Err(e) => err_text(&format!("JSON serialization error: {e}")),
	}
}

/// Return a successful text response.
pub fn ok_text(msg: impl Into<String>) -> Result<CallToolResult, McpError> {
	Ok(CallToolResult::success(vec![Content::text(msg.into())]))
}

/// Return an error text response.
pub fn err_text(msg: &str) -> Result<CallToolResult, McpError> {
	Ok(CallToolResult::error(vec![Content::text(msg.to_string())]))
}

/// Return a dry-run notice.
pub fn dry_run_text(tool: &str) -> Result<CallToolResult, McpError> {
	ok_text(format!("[dry-run] {tool} would execute but dry-run is active"))
}

/// Return an error response with OS-level error mapping for agent-friendly messages.
pub fn mapped_err(
	err: &MyceliumError,
	ctx: Option<&ErrorContext>,
) -> Result<CallToolResult, McpError> {
	let msg = map_error_message(err, ctx);
	err_text(&msg)
}
