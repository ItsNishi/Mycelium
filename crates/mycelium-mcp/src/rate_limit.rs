//! Sliding-window rate limiter for destructive operations.
//!
//! Uses `Mutex<HashMap<String, VecDeque<Instant>>>` -- zero contention because
//! the MCP server processes one request at a time per agent session.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use mycelium_core::policy::RateLimit;

/// Error returned when a rate limit is exceeded.
#[derive(Debug)]
pub struct RateLimitError {
	pub tool: String,
	pub max_calls: u32,
	pub window_secs: u64,
}

impl std::fmt::Display for RateLimitError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(
			f,
			"rate limit exceeded: {} allows at most {} calls per {} seconds",
			self.tool, self.max_calls, self.window_secs
		)
	}
}

/// Sliding-window rate limiter.
pub struct RateLimiter {
	configs: HashMap<String, RateLimit>,
	windows: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl RateLimiter {
	/// Create a new rate limiter from policy config.
	pub fn new(configs: HashMap<String, RateLimit>) -> Self {
		Self {
			configs,
			windows: Mutex::new(HashMap::new()),
		}
	}

	/// Check (and record) a call to `tool_name`.
	///
	/// Returns `Ok(())` if allowed, `Err(RateLimitError)` if the limit is exceeded.
	/// Tools with no configured limit always pass.
	pub fn check(&self, tool_name: &str) -> Result<(), RateLimitError> {
		let config = match self.configs.get(tool_name) {
			Some(c) => c,
			None => return Ok(()),
		};

		let now = Instant::now();
		let window = Duration::from_secs(config.window_secs);
		let cutoff = now - window;

		let mut windows = self.windows.lock().unwrap();
		let deque = windows.entry(tool_name.to_string()).or_default();

		// Evict expired entries.
		while deque.front().is_some_and(|t| *t < cutoff) {
			deque.pop_front();
		}

		if deque.len() >= config.max_calls as usize {
			return Err(RateLimitError {
				tool: tool_name.to_string(),
				max_calls: config.max_calls,
				window_secs: config.window_secs,
			});
		}

		deque.push_back(now);
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn make_limiter(tool: &str, max: u32, window: u64) -> RateLimiter {
		let mut configs = HashMap::new();
		configs.insert(
			tool.to_string(),
			RateLimit {
				max_calls: max,
				window_secs: window,
			},
		);
		RateLimiter::new(configs)
	}

	#[test]
	fn test_no_config_passes() {
		let limiter = RateLimiter::new(HashMap::new());
		assert!(limiter.check("anything").is_ok());
	}

	#[test]
	fn test_within_limit_passes() {
		let limiter = make_limiter("process_kill", 3, 60);
		assert!(limiter.check("process_kill").is_ok());
		assert!(limiter.check("process_kill").is_ok());
		assert!(limiter.check("process_kill").is_ok());
	}

	#[test]
	fn test_over_limit_rejected() {
		let limiter = make_limiter("process_kill", 2, 60);
		assert!(limiter.check("process_kill").is_ok());
		assert!(limiter.check("process_kill").is_ok());
		let err = limiter.check("process_kill").unwrap_err();
		assert_eq!(err.max_calls, 2);
		assert_eq!(err.tool, "process_kill");
	}

	#[test]
	fn test_different_tool_independent() {
		let limiter = make_limiter("process_kill", 1, 60);
		assert!(limiter.check("process_kill").is_ok());
		assert!(limiter.check("process_kill").is_err());
		// unconfigured tool still passes
		assert!(limiter.check("memory_write").is_ok());
	}

	#[test]
	fn test_window_expiry() {
		// With a very large window (60s) and max_calls=2, two calls pass,
		// third is rejected. This verifies basic sliding-window counting.
		let limiter = make_limiter("process_kill", 2, 60);
		assert!(limiter.check("process_kill").is_ok());
		assert!(limiter.check("process_kill").is_ok());
		assert!(limiter.check("process_kill").is_err());

		// Manually expire all entries by replacing the window contents.
		{
			let mut windows = limiter.windows.lock().unwrap();
			let deque = windows.get_mut("process_kill").unwrap();
			// Drain all entries so the window is empty.
			deque.clear();
		}

		// After clearing, calls should pass again.
		assert!(limiter.check("process_kill").is_ok());
	}

	#[test]
	fn test_error_display() {
		let err = RateLimitError {
			tool: "memory_write".to_string(),
			max_calls: 10,
			window_secs: 60,
		};
		let msg = err.to_string();
		assert!(msg.contains("memory_write"));
		assert!(msg.contains("10"));
		assert!(msg.contains("60"));
	}
}
