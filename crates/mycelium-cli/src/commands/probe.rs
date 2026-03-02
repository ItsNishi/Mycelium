//! CLI probe subcommands for eBPF attach/detach/list/events.

#![cfg_attr(not(feature = "ebpf"), allow(dead_code, unused_imports))]

use clap::Subcommand;
use mycelium_core::platform::ProbePlatform;
use mycelium_core::types::{ProbeConfig, ProbeEvent, ProbeHandle, ProbeInfo, ProbeType};

use crate::output::*;

#[derive(Subcommand)]
pub enum ProbeCmd {
	/// Attach an eBPF probe
	Attach {
		/// Probe type: syscall-trace or network-monitor
		#[arg(long = "type")]
		probe_type: String,
		/// Target: PID for syscall-trace, interface name for network-monitor
		#[arg(long)]
		target: Option<String>,
		/// Filter: comma-separated syscall names/numbers or protocol:port list
		#[arg(long)]
		filter: Option<String>,
	},
	/// Detach a running probe
	Detach {
		/// Probe handle ID
		handle: u64,
	},
	/// List active probes
	List,
	/// Read events from a probe
	Events {
		/// Probe handle ID
		handle: u64,
		/// Continuously poll for events (like tail -f)
		#[arg(long)]
		follow: bool,
		/// Maximum number of events to read
		#[arg(long)]
		limit: Option<usize>,
	},
}

impl ProbeCmd {
	pub fn run(&self, platform: &dyn ProbePlatform, format: OutputFormat, dry_run: bool) {
		match self {
			Self::Attach {
				probe_type,
				target,
				filter,
			} => {
				let pt = match probe_type.as_str() {
					"syscall-trace" => ProbeType::SyscallTrace,
					"network-monitor" => ProbeType::NetworkMonitor,
					other => {
						eprintln!("error: unknown probe type: {other}");
						eprintln!("valid types: syscall-trace, network-monitor");
						return;
					}
				};

				if dry_run {
					println!("[dry-run] would attach {probe_type} probe");
					return;
				}

				let config = ProbeConfig {
					probe_type: pt,
					target: target.clone(),
					filter: filter.clone(),
				};

				match platform.attach_probe(&config) {
					Ok(handle) => println!("probe attached: handle={}", handle.0),
					Err(e) => eprintln!("error: {e}"),
				}
			}

			Self::Detach { handle } => {
				if dry_run {
					println!("[dry-run] would detach probe {handle}");
					return;
				}
				match platform.detach_probe(ProbeHandle(*handle)) {
					Ok(()) => println!("probe {handle} detached"),
					Err(e) => eprintln!("error: {e}"),
				}
			}

			Self::List => match platform.list_probes() {
				Ok(probes) => print_list(&probes, format),
				Err(e) => eprintln!("error: {e}"),
			},

			Self::Events {
				handle,
				follow,
				limit,
			} => {
				let probe_handle = ProbeHandle(*handle);
				let mut total = 0usize;

				loop {
					match platform.read_probe_events(&probe_handle) {
						Ok(events) => {
							for event in &events {
								print_probe_event(event, format);
								total += 1;
								if let Some(max) = limit
									&& total >= *max
								{
									return;
								}
							}
						}
						Err(e) => {
							eprintln!("error: {e}");
							return;
						}
					}

					if !follow {
						break;
					}

					// Poll interval in follow mode.
					std::thread::sleep(std::time::Duration::from_millis(200));
				}
			}
		}
	}
}

fn print_probe_event(event: &ProbeEvent, format: OutputFormat) {
	match format {
		OutputFormat::Json => {
			if let Ok(json) = serde_json::to_string(event) {
				println!("{json}");
			}
		}
		OutputFormat::Table => {
			println!(
				"[{}] pid={} ({}) {}: {}",
				event.timestamp, event.pid, event.process_name, event.event_type, event.details,
			);
		}
	}
}

impl TableDisplay for ProbeInfo {
	fn print_header() {
		println!("{:<10} {:<20} {:<15} EVENTS", "HANDLE", "TYPE", "TARGET");
	}

	fn print_row(&self) {
		let type_str = match self.probe_type {
			ProbeType::SyscallTrace => "syscall-trace",
			ProbeType::NetworkMonitor => "network-monitor",
		};
		let target = self.target.as_deref().unwrap_or("-");
		println!(
			"{:<10} {:<20} {:<15} {}",
			self.handle.0, type_str, target, self.events_captured,
		);
	}
}
