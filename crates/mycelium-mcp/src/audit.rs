//! Stderr-based audit log for the MCP server.

use mycelium_core::audit::{AuditEntry, AuditLog};

/// Audit log that writes structured entries via tracing to stderr.
pub struct StderrAuditLog;

impl AuditLog for StderrAuditLog {
	fn log(&self, entry: &AuditEntry) {
		tracing::info!(
			agent = %entry.agent,
			profile = %entry.profile,
			tool = %entry.tool,
			resource = entry.resource.as_deref().unwrap_or("-"),
			allowed = entry.allowed,
			dry_run = entry.dry_run,
			outcome = ?entry.outcome,
			reason = entry.reason.as_deref().unwrap_or("-"),
			"audit"
		);
	}
}
