//! Log tool handlers.

use rmcp::ErrorData as McpError;
use rmcp::model::CallToolResult;

use super::response::{dry_run_text, err_text, ok_json};
use crate::MyceliumMcpService;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct LogReadRequest {
	/// Journal unit filter
	#[schemars(description = "Filter by systemd unit name")]
	pub unit: Option<String>,
	/// Minimum log level
	#[schemars(description = "Minimum severity: emergency, alert, critical, error, warning, notice, info, debug")]
	pub level: Option<String>,
	/// Start timestamp (epoch seconds)
	#[schemars(description = "Start timestamp (Unix epoch seconds)")]
	pub since: Option<u64>,
	/// End timestamp (epoch seconds)
	#[schemars(description = "End timestamp (Unix epoch seconds)")]
	pub until: Option<u64>,
	/// Maximum entries to return
	#[schemars(description = "Maximum number of log entries to return")]
	pub limit: Option<u32>,
	/// Grep pattern
	#[schemars(description = "Filter log messages matching this pattern")]
	pub grep: Option<String>,
}

pub async fn handle_read(svc: &MyceliumMcpService, req: LogReadRequest) -> Result<CallToolResult, McpError> {
	use mycelium_core::policy::rule::ResourceContext;
	use mycelium_core::types::{LogLevel, LogQuery};

	let resource = req.unit.as_deref().map(|u| format!("unit:{u}"));
	let ctx = ResourceContext {
		log_source: req.unit.clone(),
		..Default::default()
	};
	if let Some(result) = svc.check_policy_with_context("log_read", resource.as_deref(), Some(&ctx)) {
		return result;
	}
	if svc.is_dry_run() {
		return dry_run_text("log_read");
	}

	let level = if let Some(ref lvl) = req.level {
		Some(match lvl.to_lowercase().as_str() {
			"emergency" | "emerg" => LogLevel::Emergency,
			"alert" => LogLevel::Alert,
			"critical" | "crit" => LogLevel::Critical,
			"error" | "err" => LogLevel::Error,
			"warning" | "warn" => LogLevel::Warning,
			"notice" => LogLevel::Notice,
			"info" => LogLevel::Info,
			"debug" => LogLevel::Debug,
			other => return err_text(&format!("unknown log level: {other}")),
		})
	} else {
		None
	};

	let query = LogQuery {
		unit: req.unit.clone(),
		level,
		since: req.since,
		until: req.until,
		limit: req.limit,
		grep: req.grep.clone(),
	};

	let platform = svc.platform();
	match tokio::task::spawn_blocking(move || platform.read_logs(&query)).await {
		Ok(Ok(entries)) => {
			svc.log_success("log_read", resource.as_deref());
			ok_json(&entries)
		}
		Ok(Err(e)) => {
			svc.log_failure("log_read", &e.to_string());
			err_text(&e.to_string())
		}
		Err(e) => svc.handle_join_error("log_read", e),
	}
}
