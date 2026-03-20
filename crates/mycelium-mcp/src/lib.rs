//! Mycelium MCP server library.

pub mod audit;
pub mod error_mapping;
pub mod rate_limit;
pub mod tools;

use std::sync::Arc;

use rmcp::ErrorData as McpError;
use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::*;
use rmcp::{ServerHandler, tool_handler};

use mycelium_core::audit::{AuditEntry, AuditLog, AuditOutcome};
use mycelium_core::platform::{Platform, ProbePlatform};
use mycelium_core::policy::Policy;

use rate_limit::RateLimiter;
use tools::response::err_text;

/// The MCP service that wraps Mycelium's platform, policy, and audit layers.
#[derive(Clone)]
pub struct MyceliumMcpService {
	platform: Arc<dyn Platform>,
	probe_platform: Option<Arc<dyn ProbePlatform>>,
	policy: Arc<Policy>,
	audit: Arc<dyn AuditLog>,
	agent_name: String,
	rate_limiter: Arc<RateLimiter>,
	tool_router: ToolRouter<Self>,
}

impl MyceliumMcpService {
	pub fn new(
		platform: Arc<dyn Platform>,
		policy: Arc<Policy>,
		audit: Arc<dyn AuditLog>,
		agent_name: String,
	) -> Self {
		let rate_limiter = Arc::new(RateLimiter::new(policy.rate_limits.clone()));
		Self {
			platform,
			probe_platform: None,
			policy,
			audit,
			agent_name,
			rate_limiter,
			tool_router: Self::create_tool_router(),
		}
	}

	/// Set the probe platform for eBPF support.
	pub fn with_probe_platform(mut self, probe: Arc<dyn ProbePlatform>) -> Self {
		self.probe_platform = Some(probe);
		self
	}

	/// Get a clone of the platform Arc for use in spawn_blocking.
	pub fn platform(&self) -> Arc<dyn Platform> {
		Arc::clone(&self.platform)
	}

	/// Get a clone of the probe platform Arc, if available.
	pub fn probe_platform(&self) -> Option<Arc<dyn ProbePlatform>> {
		self.probe_platform.as_ref().map(Arc::clone)
	}

	/// Check policy for a tool call. Returns Some(result) if denied or dry-run,
	/// None if allowed and should proceed.
	pub fn check_policy(
		&self,
		tool_name: &str,
		resource: Option<&str>,
	) -> Option<Result<CallToolResult, McpError>> {
		self.check_policy_with_context(tool_name, resource, None)
	}

	/// Check policy with a full resource context for filter evaluation.
	pub fn check_policy_with_context(
		&self,
		tool_name: &str,
		resource: Option<&str>,
		context: Option<&mycelium_core::policy::rule::ResourceContext>,
	) -> Option<Result<CallToolResult, McpError>> {
		let effective = self.policy.effective(&self.agent_name);
		let decision = effective.evaluate(tool_name, context);

		if !decision.allowed {
			let reason = decision.reason.unwrap_or_else(|| "policy denied".into());

			self.audit.log(&AuditEntry {
				timestamp: current_timestamp(),
				agent: self.agent_name.clone(),
				profile: self.agent_name.clone(),
				tool: tool_name.into(),
				resource: resource.map(|s| s.into()),
				allowed: false,
				dry_run: false,
				reason: Some(reason.clone()),
				outcome: AuditOutcome::Denied,
			});

			return Some(err_text(&format!("denied: {reason}")));
		}

		None
	}

	/// Check the rate limiter for a destructive operation.
	/// Returns Some(result) if rate limited, None if allowed.
	pub fn check_rate_limit(&self, tool_name: &str) -> Option<Result<CallToolResult, McpError>> {
		match self.rate_limiter.check(tool_name) {
			Ok(()) => None,
			Err(e) => {
				let msg = e.to_string();
				self.audit.log(&AuditEntry {
					timestamp: current_timestamp(),
					agent: self.agent_name.clone(),
					profile: self.agent_name.clone(),
					tool: tool_name.into(),
					resource: None,
					allowed: true,
					dry_run: false,
					reason: Some(msg.clone()),
					outcome: AuditOutcome::RateLimited,
				});
				Some(err_text(&msg))
			}
		}
	}

	/// Whether the effective policy is in dry-run mode.
	pub fn is_dry_run(&self) -> bool {
		self.policy.effective(&self.agent_name).is_dry_run()
	}

	/// Log a successful tool invocation.
	pub fn log_success(&self, tool_name: &str, resource: Option<&str>) {
		self.audit.log(&AuditEntry {
			timestamp: current_timestamp(),
			agent: self.agent_name.clone(),
			profile: self.agent_name.clone(),
			tool: tool_name.into(),
			resource: resource.map(|s| s.into()),
			allowed: true,
			dry_run: false,
			reason: None,
			outcome: AuditOutcome::Success,
		});
	}

	/// Handle a task join error: log the failure and return an error response.
	pub fn handle_join_error(
		&self,
		tool_name: &str,
		err: tokio::task::JoinError,
	) -> Result<CallToolResult, McpError> {
		let msg = format!("task join error: {err}");
		self.log_failure(tool_name, &msg);
		err_text(&msg)
	}

	/// Log a failed tool invocation (allowed but errored).
	pub fn log_failure(&self, tool_name: &str, error: &str) {
		self.audit.log(&AuditEntry {
			timestamp: current_timestamp(),
			agent: self.agent_name.clone(),
			profile: self.agent_name.clone(),
			tool: tool_name.into(),
			resource: None,
			allowed: true,
			dry_run: false,
			reason: Some(error.into()),
			outcome: AuditOutcome::Failed,
		});
	}
}

#[tool_handler]
impl ServerHandler for MyceliumMcpService {
	fn get_info(&self) -> ServerInfo {
		ServerInfo {
			instructions: Some(
				"Mycelium: structured, typed access to OS kernel data and controls. \
				 All responses are JSON. Write operations respect policy and audit logging."
					.into(),
			),
			capabilities: ServerCapabilities::builder().enable_tools().build(),
			..Default::default()
		}
	}
}

fn current_timestamp() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs()
}
