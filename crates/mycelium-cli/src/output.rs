//! Output formatting: JSON, table, or plain text.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
	Json,
	Table,
}

/// Print a serializable value in the requested format.
pub fn print_output<T: Serialize + TableDisplay>(value: &T, format: OutputFormat) {
	match format {
		OutputFormat::Json => print_json(value),
		OutputFormat::Table => value.print_table(),
	}
}

/// Print a list of serializable values.
pub fn print_list<T: Serialize + TableDisplay>(items: &[T], format: OutputFormat) {
	match format {
		OutputFormat::Json => print_json(items),
		OutputFormat::Table => {
			if items.is_empty() {
				println!("(no results)");
				return;
			}
			T::print_header();
			for item in items {
				item.print_row();
			}
		}
	}
}

fn print_json<T: Serialize + ?Sized>(value: &T) {
	match serde_json::to_string_pretty(value) {
		Ok(json) => println!("{json}"),
		Err(e) => eprintln!("error serializing JSON: {e}"),
	}
}

/// Trait for types that can render themselves as table rows.
pub trait TableDisplay {
	fn print_header();
	fn print_row(&self);

	/// Single-item display (default: header + row).
	fn print_table(&self) {
		Self::print_header();
		self.print_row();
	}
}

/// Helper to truncate a string to a max width.
pub fn truncate(s: &str, max: usize) -> String {
	if s.len() <= max {
		s.to_string()
	} else {
		format!("{}...", &s[..max.saturating_sub(3)])
	}
}

/// Format bytes into human-readable form (KiB, MiB, GiB, TiB).
pub fn human_bytes(bytes: u64) -> String {
	const KIB: u64 = 1024;
	const MIB: u64 = 1024 * KIB;
	const GIB: u64 = 1024 * MIB;
	const TIB: u64 = 1024 * GIB;

	if bytes >= TIB {
		format!("{:.1} TiB", bytes as f64 / TIB as f64)
	} else if bytes >= GIB {
		format!("{:.1} GiB", bytes as f64 / GIB as f64)
	} else if bytes >= MIB {
		format!("{:.1} MiB", bytes as f64 / MIB as f64)
	} else if bytes >= KIB {
		format!("{:.1} KiB", bytes as f64 / KIB as f64)
	} else {
		format!("{bytes} B")
	}
}

/// Format seconds into human-readable uptime.
pub fn human_uptime(seconds: u64) -> String {
	let days = seconds / 86400;
	let hours = (seconds % 86400) / 3600;
	let minutes = (seconds % 3600) / 60;

	if days > 0 {
		format!("{days}d {hours}h {minutes}m")
	} else if hours > 0 {
		format!("{hours}h {minutes}m")
	} else {
		format!("{minutes}m")
	}
}
