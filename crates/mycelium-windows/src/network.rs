//! Network information via sysinfo, WinAPI, WMI, and netsh.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;

use sysinfo::Networks;
use wmi::{COMLibrary, WMIConnection};

use mycelium_core::error::{MyceliumError, Result};
use mycelium_core::types::{
	Connection, ConnectionState, FirewallAction, FirewallRule, InterfaceState, NetworkInterface,
	OpenPort, Protocol, Route,
};

pub fn list_interfaces() -> Result<Vec<NetworkInterface>> {
	let networks = Networks::new_with_refreshed_list();

	let ifaces = networks
		.iter()
		.map(|(name, data)| {
			let mac = data.mac_address().to_string();
			let ipv4: Vec<String> = data
				.ip_networks()
				.iter()
				.filter(|ip| ip.addr.is_ipv4())
				.map(|ip| format!("{}/{}", ip.addr, ip.prefix))
				.collect();
			let ipv6: Vec<String> = data
				.ip_networks()
				.iter()
				.filter(|ip| ip.addr.is_ipv6())
				.map(|ip| format!("{}/{}", ip.addr, ip.prefix))
				.collect();

			NetworkInterface {
				name: name.to_string(),
				mac_address: if mac == "00:00:00:00:00:00" {
					None
				} else {
					Some(mac)
				},
				ipv4_addresses: ipv4,
				ipv6_addresses: ipv6,
				mtu: 0, // sysinfo doesn't expose MTU
				state: if data.total_received() > 0 || data.total_transmitted() > 0 {
					InterfaceState::Up
				} else {
					InterfaceState::Unknown
				},
				rx_bytes: data.total_received(),
				tx_bytes: data.total_transmitted(),
				rx_packets: data.total_packets_received(),
				tx_packets: data.total_packets_transmitted(),
				rx_errors: data.total_errors_on_received(),
				tx_errors: data.total_errors_on_transmitted(),
			}
		})
		.collect();

	Ok(ifaces)
}

/// Parse `netstat -ano` output to get connections.
pub fn list_connections() -> Result<Vec<Connection>> {
	let output = Command::new("netstat")
		.args(["-ano"])
		.output()
		.map_err(|e| MyceliumError::OsError {
			code: e.raw_os_error().unwrap_or(-1),
			message: format!("failed to run netstat: {e}"),
		})?;

	let stdout = String::from_utf8_lossy(&output.stdout);
	let mut connections = Vec::new();

	for line in stdout.lines() {
		let parts: Vec<&str> = line.split_whitespace().collect();
		if parts.len() < 4 {
			continue;
		}

		let proto_str = parts[0];
		let (protocol, has_state) = match proto_str {
			"TCP" => (Protocol::Tcp, true),
			"UDP" => (Protocol::Udp, false),
			_ => continue,
		};

		let (local_addr, local_port) = match parse_address(parts[1]) {
			Some(v) => v,
			None => continue,
		};

		let (remote_addr, remote_port) = if has_state {
			parse_address(parts[2]).unwrap_or_default()
		} else {
			(String::from("*"), 0)
		};

		// Detect IPv6
		let protocol = if local_addr.contains(':') && local_addr != "0.0.0.0" {
			match protocol {
				Protocol::Tcp => Protocol::Tcp6,
				Protocol::Udp => Protocol::Udp6,
				other => other,
			}
		} else {
			protocol
		};

		let state = if has_state {
			let state_str = parts[3];
			parse_connection_state(state_str)
		} else {
			ConnectionState::Unknown
		};

		let pid_idx = if has_state { 4 } else { 3 };
		let pid = parts.get(pid_idx).and_then(|s| s.parse::<u32>().ok());

		connections.push(Connection {
			protocol,
			local_address: local_addr,
			local_port,
			remote_address: remote_addr,
			remote_port,
			state,
			pid,
			process_name: None,
		});
	}

	Ok(connections)
}

fn parse_address(addr: &str) -> Option<(String, u16)> {
	// Handles both IPv4 (1.2.3.4:port) and IPv6 ([::]:port)
	if let Some(bracket_end) = addr.rfind(']') {
		// IPv6: [::1]:port
		let ip = &addr[1..bracket_end];
		let port_str = &addr[bracket_end + 2..]; // skip ]:
		let port = port_str.parse().ok()?;
		Some((ip.to_string(), port))
	} else if let Some(colon) = addr.rfind(':') {
		let ip = &addr[..colon];
		let port = addr[colon + 1..].parse().ok()?;
		Some((ip.to_string(), port))
	} else {
		None
	}
}

fn parse_connection_state(s: &str) -> ConnectionState {
	match s {
		"ESTABLISHED" => ConnectionState::Established,
		"SYN_SENT" => ConnectionState::SynSent,
		"SYN_RECV" | "SYN_RECEIVED" => ConnectionState::SynRecv,
		"FIN_WAIT_1" | "FIN_WAIT1" => ConnectionState::FinWait1,
		"FIN_WAIT_2" | "FIN_WAIT2" => ConnectionState::FinWait2,
		"TIME_WAIT" => ConnectionState::TimeWait,
		"CLOSE" | "CLOSED" => ConnectionState::Close,
		"CLOSE_WAIT" => ConnectionState::CloseWait,
		"LAST_ACK" => ConnectionState::LastAck,
		"LISTENING" | "LISTEN" => ConnectionState::Listen,
		"CLOSING" => ConnectionState::Closing,
		_ => ConnectionState::Unknown,
	}
}

/// Parse `route print` output for routing table.
pub fn list_routes() -> Result<Vec<Route>> {
	let output = Command::new("route")
		.arg("print")
		.output()
		.map_err(|e| MyceliumError::OsError {
			code: e.raw_os_error().unwrap_or(-1),
			message: format!("failed to run route print: {e}"),
		})?;

	let stdout = String::from_utf8_lossy(&output.stdout);
	let mut routes = Vec::new();
	let mut in_ipv4_section = false;

	for line in stdout.lines() {
		let trimmed = line.trim();

		if trimmed.starts_with("Network Destination") {
			in_ipv4_section = true;
			continue;
		}

		if trimmed.is_empty() && in_ipv4_section {
			in_ipv4_section = false;
			continue;
		}

		if !in_ipv4_section {
			continue;
		}

		let parts: Vec<&str> = trimmed.split_whitespace().collect();
		if parts.len() < 4 {
			continue;
		}

		routes.push(Route {
			destination: parts[0].to_string(),
			netmask: parts[1].to_string(),
			gateway: parts[2].to_string(),
			interface: parts[3].to_string(),
			metric: parts.get(4).and_then(|s| s.parse().ok()).unwrap_or(0),
			flags: String::new(),
		});
	}

	Ok(routes)
}

pub fn list_open_ports() -> Result<Vec<OpenPort>> {
	let connections = list_connections()?;

	let ports = connections
		.into_iter()
		.filter(|c| c.state == ConnectionState::Listen)
		.map(|c| OpenPort {
			protocol: c.protocol,
			address: c.local_address,
			port: c.local_port,
			pid: c.pid,
			process_name: c.process_name,
		})
		.collect();

	Ok(ports)
}

/// WMI-based firewall rule struct for deserialization.
#[derive(serde::Deserialize)]
#[allow(non_snake_case)]
struct WmiFirewallRule {
	InstanceID: Option<String>,
	DisplayName: Option<String>,
	Direction: Option<u16>,
	Protocol: Option<u16>,
	Action: Option<u16>,
	Enabled: Option<u16>,
	Description: Option<String>,
}

pub fn list_firewall_rules() -> Result<Vec<FirewallRule>> {
	let com = COMLibrary::new().map_err(|e| {
		MyceliumError::OsError {
			code: -1,
			message: format!("COM init failed: {e}"),
		}
	})?;

	let wmi = WMIConnection::with_namespace_path(
		"ROOT\\StandardCimv2",
		com,
	)
	.map_err(|e| {
		MyceliumError::OsError {
			code: -1,
			message: format!("WMI connection failed: {e}"),
		}
	})?;

	let results: Vec<WmiFirewallRule> = wmi
		.raw_query("SELECT InstanceID, DisplayName, Direction, Protocol, Action, Enabled, Description FROM MSFT_NetFirewallRule")
		.map_err(|e| {
			MyceliumError::OsError {
				code: -1,
				message: format!("WMI firewall query failed: {e}"),
			}
		})?;

	let rules = results
		.into_iter()
		.map(|r| {
			let direction = match r.Direction.unwrap_or(0) {
				1 => "Inbound",
				2 => "Outbound",
				_ => "Unknown",
			};

			let action = match r.Action.unwrap_or(0) {
				2 => FirewallAction::Accept,
				3 => FirewallAction::Reject,
				4 => FirewallAction::Drop,
				_ => FirewallAction::Accept,
			};

			let proto = r.Protocol.map(|p| match p {
				6 => "tcp".to_string(),
				17 => "udp".to_string(),
				1 => "icmp".to_string(),
				_ => p.to_string(),
			});

			FirewallRule {
				id: r.InstanceID.unwrap_or_default(),
				chain: direction.to_string(),
				protocol: proto,
				source: None,
				destination: None,
				port: None,
				action,
				comment: r.Description.or(r.DisplayName),
			}
		})
		.collect();

	Ok(rules)
}

pub fn add_firewall_rule(rule: &FirewallRule) -> Result<()> {
	let direction = if rule.chain.eq_ignore_ascii_case("inbound") || rule.chain == "INPUT" {
		"in"
	} else {
		"out"
	};

	let action = match rule.action {
		FirewallAction::Accept => "allow",
		FirewallAction::Drop | FirewallAction::Reject => "block",
		FirewallAction::Log => "allow",
	};

	let mut args = vec![
		"advfirewall".to_string(),
		"firewall".to_string(),
		"add".to_string(),
		"rule".to_string(),
		format!(
			"name={}",
			rule.comment.as_deref().unwrap_or(&rule.id)
		),
		format!("dir={direction}"),
		format!("action={action}"),
	];

	if let Some(ref proto) = rule.protocol {
		args.push(format!("protocol={proto}"));
	}

	if let Some(port) = rule.port {
		args.push(format!("localport={port}"));
	}

	if let Some(ref src) = rule.source {
		args.push(format!("remoteip={src}"));
	}

	let output = Command::new("netsh")
		.args(&args)
		.output()
		.map_err(|e| MyceliumError::OsError {
			code: e.raw_os_error().unwrap_or(-1),
			message: format!("failed to run netsh: {e}"),
		})?;

	if output.status.success() {
		Ok(())
	} else {
		let stderr = String::from_utf8_lossy(&output.stderr);
		Err(MyceliumError::OsError {
			code: output.status.code().unwrap_or(-1),
			message: format!("netsh add rule failed: {stderr}"),
		})
	}
}

pub fn remove_firewall_rule(rule_id: &str) -> Result<()> {
	let output = Command::new("netsh")
		.args([
			"advfirewall",
			"firewall",
			"delete",
			"rule",
			&format!("name={rule_id}"),
		])
		.output()
		.map_err(|e| MyceliumError::OsError {
			code: e.raw_os_error().unwrap_or(-1),
			message: format!("failed to run netsh: {e}"),
		})?;

	if output.status.success() {
		Ok(())
	} else {
		let stderr = String::from_utf8_lossy(&output.stderr);
		Err(MyceliumError::OsError {
			code: output.status.code().unwrap_or(-1),
			message: format!("netsh delete rule failed: {stderr}"),
		})
	}
}
