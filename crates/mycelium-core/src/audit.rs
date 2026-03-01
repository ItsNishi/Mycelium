//! Audit logging types.

/// Outcome of a tool invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AuditOutcome {
	Success,
	Denied,
	DryRun,
	Failed,
}

/// A single audit log entry.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuditEntry {
	pub timestamp: u64,
	pub agent: String,
	pub profile: String,
	pub tool: String,
	pub resource: Option<String>,
	pub allowed: bool,
	pub dry_run: bool,
	pub reason: Option<String>,
	pub outcome: AuditOutcome,
}

/// Trait for audit log backends.
pub trait AuditLog: Send + Sync {
	/// Record an audit entry.
	fn log(&self, entry: &AuditEntry);
}
