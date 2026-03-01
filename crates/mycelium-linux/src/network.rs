//! Network queries via /proc/net/* and /sys/class/net/*.

use mycelium_core::error::{MyceliumError, Result};
use mycelium_core::types::*;
use std::fs;
use std::path::Path;

fn read_sys_net(iface: &str, file: &str) -> Option<String> {
	fs::read_to_string(format!("/sys/class/net/{iface}/{file}"))
		.ok()
		.map(|s| s.trim().to_string())
}

fn read_sys_net_stat(iface: &str, file: &str) -> u64 {
	fs::read_to_string(format!("/sys/class/net/{iface}/statistics/{file}"))
		.ok()
		.and_then(|s| s.trim().parse().ok())
		.unwrap_or(0)
}

pub fn list_interfaces() -> Result<Vec<NetworkInterface>> {
	let mut interfaces = Vec::new();

	for entry in fs::read_dir("/sys/class/net")? {
		let entry = entry?;
		let name = entry.file_name().to_string_lossy().to_string();

		let mac = read_sys_net(&name, "address")
			.filter(|a| a != "00:00:00:00:00:00");

		let mtu = read_sys_net(&name, "mtu")
			.and_then(|s| s.parse().ok())
			.unwrap_or(0);

		let operstate = read_sys_net(&name, "operstate").unwrap_or_default();
		let state = match operstate.as_str() {
			"up" => InterfaceState::Up,
			"down" => InterfaceState::Down,
			_ => InterfaceState::Unknown,
		};

		// Get IP addresses from /proc/net/if_inet6 and ip parsing
		let (ipv4, ipv6) = get_ip_addresses(&name);

		interfaces.push(NetworkInterface {
			name,
			mac_address: mac,
			ipv4_addresses: ipv4,
			ipv6_addresses: ipv6,
			mtu,
			state,
			rx_bytes: read_sys_net_stat(&entry.file_name().to_string_lossy(), "rx_bytes"),
			tx_bytes: read_sys_net_stat(&entry.file_name().to_string_lossy(), "tx_bytes"),
			rx_packets: read_sys_net_stat(&entry.file_name().to_string_lossy(), "rx_packets"),
			tx_packets: read_sys_net_stat(&entry.file_name().to_string_lossy(), "tx_packets"),
			rx_errors: read_sys_net_stat(&entry.file_name().to_string_lossy(), "rx_errors"),
			tx_errors: read_sys_net_stat(&entry.file_name().to_string_lossy(), "tx_errors"),
		});
	}

	interfaces.sort_by(|a, b| a.name.cmp(&b.name));
	Ok(interfaces)
}

fn get_ip_addresses(iface: &str) -> (Vec<String>, Vec<String>) {
	let mut ipv4 = Vec::new();
	let mut ipv6 = Vec::new();

	// Parse /proc/net/fib_trie is complex; use a simpler approach via
	// reading the output of the address files
	// For IPv4: parse /proc/net/fib_trie or use nix
	// Simpler: iterate /sys/class/net/{iface}/address won't give IP.
	// Use SIOCGIFADDR via nix or parse /proc/net/if_inet6 for IPv6

	// IPv6 from /proc/net/if_inet6
	if let Ok(content) = fs::read_to_string("/proc/net/if_inet6") {
		for line in content.lines() {
			let parts: Vec<&str> = line.split_whitespace().collect();
			if parts.len() >= 6 && parts[5] == iface {
				let hex = parts[0];
				let prefix_len = u8::from_str_radix(parts[2], 16).unwrap_or(0);
				if hex.len() == 32 {
					let formatted = format!(
						"{:}:{:}:{:}:{:}:{:}:{:}:{:}:{:}/{prefix_len}",
						&hex[0..4],
						&hex[4..8],
						&hex[8..12],
						&hex[12..16],
						&hex[16..20],
						&hex[20..24],
						&hex[24..28],
						&hex[28..32],
					);
					ipv6.push(formatted);
				}
			}
		}
	}

	// IPv4 via nix getifaddrs
	if let Ok(addrs) = nix::ifaddrs::getifaddrs() {
		for addr in addrs {
			if addr.interface_name != iface {
				continue;
			}
			if let Some(address) = &addr.address
				&& let Some(sin) = address.as_sockaddr_in()
			{
				ipv4.push(format!("{}", sin.ip()));
			}
		}
	}

	(ipv4, ipv6)
}

pub fn list_connections() -> Result<Vec<Connection>> {
	let mut connections = Vec::new();

	parse_proc_net_tcp("/proc/net/tcp", Protocol::Tcp, &mut connections)?;
	parse_proc_net_tcp("/proc/net/tcp6", Protocol::Tcp6, &mut connections)?;
	parse_proc_net_udp("/proc/net/udp", Protocol::Udp, &mut connections)?;
	parse_proc_net_udp("/proc/net/udp6", Protocol::Udp6, &mut connections)?;

	Ok(connections)
}

fn parse_hex_addr(hex: &str) -> (String, u16) {
	let parts: Vec<&str> = hex.split(':').collect();
	if parts.len() != 2 {
		return ("0.0.0.0".into(), 0);
	}

	let port = u16::from_str_radix(parts[1], 16).unwrap_or(0);
	let addr_hex = parts[0];

	if addr_hex.len() == 8 {
		// IPv4: stored as little-endian hex
		let n = u32::from_str_radix(addr_hex, 16).unwrap_or(0);
		let ip = std::net::Ipv4Addr::from(n.to_be());
		(ip.to_string(), port)
	} else if addr_hex.len() == 32 {
		// IPv6
		let mut octets = [0u8; 16];
		for i in 0..4 {
			let word = u32::from_str_radix(&addr_hex[i * 8..(i + 1) * 8], 16).unwrap_or(0);
			let bytes = word.to_be_bytes();
			octets[i * 4] = bytes[3];
			octets[i * 4 + 1] = bytes[2];
			octets[i * 4 + 2] = bytes[1];
			octets[i * 4 + 3] = bytes[0];
		}
		let ip = std::net::Ipv6Addr::from(octets);
		(ip.to_string(), port)
	} else {
		("0.0.0.0".into(), port)
	}
}

fn parse_tcp_state(state: u8) -> ConnectionState {
	match state {
		0x01 => ConnectionState::Established,
		0x02 => ConnectionState::SynSent,
		0x03 => ConnectionState::SynRecv,
		0x04 => ConnectionState::FinWait1,
		0x05 => ConnectionState::FinWait2,
		0x06 => ConnectionState::TimeWait,
		0x07 => ConnectionState::Close,
		0x08 => ConnectionState::CloseWait,
		0x09 => ConnectionState::LastAck,
		0x0A => ConnectionState::Listen,
		0x0B => ConnectionState::Closing,
		_ => ConnectionState::Unknown,
	}
}

fn inode_to_pid(inode: &str) -> Option<u32> {
	let target = format!("socket:[{inode}]");
	if let Ok(procs) = fs::read_dir("/proc") {
		for entry in procs.flatten() {
			let pid_str = entry.file_name();
			let Some(pid) = pid_str.to_str().and_then(|s| s.parse::<u32>().ok()) else {
				continue;
			};
			let fd_dir = format!("/proc/{pid}/fd");
			if let Ok(fds) = fs::read_dir(&fd_dir) {
				for fd in fds.flatten() {
					if let Ok(link) = fs::read_link(fd.path())
						&& link.to_string_lossy() == target
					{
						return Some(pid);
					}
				}
			}
		}
	}
	None
}

fn process_name_for_pid(pid: u32) -> Option<String> {
	fs::read_to_string(format!("/proc/{pid}/comm"))
		.ok()
		.map(|s| s.trim().to_string())
}

fn parse_proc_net_tcp(
	path: &str,
	protocol: Protocol,
	out: &mut Vec<Connection>,
) -> Result<()> {
	let content = match fs::read_to_string(path) {
		Ok(c) => c,
		Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
		Err(e) => return Err(e.into()),
	};

	for line in content.lines().skip(1) {
		let fields: Vec<&str> = line.split_whitespace().collect();
		if fields.len() < 10 {
			continue;
		}

		let (local_addr, local_port) = parse_hex_addr(fields[1]);
		let (remote_addr, remote_port) = parse_hex_addr(fields[2]);
		let state_num = u8::from_str_radix(fields[3], 16).unwrap_or(0);
		let inode = fields[9];

		let pid = inode_to_pid(inode);
		let process_name = pid.and_then(process_name_for_pid);

		out.push(Connection {
			protocol,
			local_address: local_addr,
			local_port,
			remote_address: remote_addr,
			remote_port,
			state: parse_tcp_state(state_num),
			pid,
			process_name,
		});
	}
	Ok(())
}

fn parse_proc_net_udp(
	path: &str,
	protocol: Protocol,
	out: &mut Vec<Connection>,
) -> Result<()> {
	let content = match fs::read_to_string(path) {
		Ok(c) => c,
		Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
		Err(e) => return Err(e.into()),
	};

	for line in content.lines().skip(1) {
		let fields: Vec<&str> = line.split_whitespace().collect();
		if fields.len() < 10 {
			continue;
		}

		let (local_addr, local_port) = parse_hex_addr(fields[1]);
		let (remote_addr, remote_port) = parse_hex_addr(fields[2]);
		let inode = fields[9];

		let pid = inode_to_pid(inode);
		let process_name = pid.and_then(process_name_for_pid);

		out.push(Connection {
			protocol,
			local_address: local_addr,
			local_port,
			remote_address: remote_addr,
			remote_port,
			state: ConnectionState::Unknown, // UDP is stateless
			pid,
			process_name,
		});
	}
	Ok(())
}

pub fn list_routes() -> Result<Vec<Route>> {
	let content = fs::read_to_string("/proc/net/route")?;
	let mut routes = Vec::new();

	for line in content.lines().skip(1) {
		let fields: Vec<&str> = line.split_whitespace().collect();
		if fields.len() < 8 {
			continue;
		}

		let parse_ip = |hex: &str| -> String {
			let n = u32::from_str_radix(hex, 16).unwrap_or(0);
			let ip = std::net::Ipv4Addr::from(n.to_be());
			ip.to_string()
		};

		routes.push(Route {
			interface: fields[0].to_string(),
			destination: parse_ip(fields[1]),
			gateway: parse_ip(fields[2]),
			flags: fields[3].to_string(),
			netmask: parse_ip(fields[7]),
			metric: fields[6].parse().unwrap_or(0),
		});
	}

	Ok(routes)
}

pub fn list_open_ports() -> Result<Vec<OpenPort>> {
	let connections = list_connections()?;
	let mut ports: Vec<OpenPort> = connections
		.into_iter()
		.filter(|c| c.state == ConnectionState::Listen || matches!(c.protocol, Protocol::Udp | Protocol::Udp6))
		.map(|c| OpenPort {
			protocol: c.protocol,
			address: c.local_address,
			port: c.local_port,
			pid: c.pid,
			process_name: c.process_name,
		})
		.collect();

	ports.sort_by_key(|p| p.port);
	ports.dedup_by(|a, b| a.port == b.port && a.address == b.address);
	Ok(ports)
}

pub fn list_firewall_rules() -> Result<Vec<FirewallRule>> {
	// Phase 1: read-only listing via iptables-save or nftables
	// Try nft first, fall back to iptables
	let nft_path = Path::new("/usr/sbin/nft");
	let ipt_path = Path::new("/usr/sbin/iptables-save");

	if nft_path.exists() {
		parse_nft_rules()
	} else if ipt_path.exists() {
		parse_iptables_rules()
	} else {
		Ok(Vec::new())
	}
}

fn parse_nft_rules() -> Result<Vec<FirewallRule>> {
	let output = std::process::Command::new("nft")
		.args(["list", "ruleset", "-a"])
		.output()
		.map_err(|e| MyceliumError::OsError {
			code: -1,
			message: format!("failed to run nft: {e}"),
		})?;

	if !output.status.success() {
		// Likely permission denied
		return Ok(Vec::new());
	}

	let stdout = String::from_utf8_lossy(&output.stdout);
	let mut rules = Vec::new();
	let mut current_chain = String::new();

	for line in stdout.lines() {
		let trimmed = line.trim();
		if trimmed.starts_with("chain ") {
			current_chain = trimmed
				.strip_prefix("chain ")
				.unwrap_or("")
				.trim_end_matches(" {")
				.trim()
				.to_string();
		} else if trimmed.contains("handle ") {
			// Basic rule parsing -- extract what we can
			let handle = trimmed
				.rsplit("handle ")
				.next()
				.and_then(|s| s.split_whitespace().next())
				.unwrap_or("0");

			let action = if trimmed.contains("accept") {
				FirewallAction::Accept
			} else if trimmed.contains("drop") {
				FirewallAction::Drop
			} else if trimmed.contains("reject") {
				FirewallAction::Reject
			} else if trimmed.contains("log") {
				FirewallAction::Log
			} else {
				continue; // Skip non-action lines
			};

			rules.push(FirewallRule {
				id: handle.to_string(),
				chain: current_chain.clone(),
				protocol: extract_word_after(trimmed, "ip protocol "),
				source: extract_word_after(trimmed, "ip saddr "),
				destination: extract_word_after(trimmed, "ip daddr "),
				port: extract_word_after(trimmed, "dport ")
					.and_then(|s| s.parse().ok()),
				action,
				comment: extract_quoted(trimmed, "comment "),
			});
		}
	}

	Ok(rules)
}

fn extract_word_after(line: &str, prefix: &str) -> Option<String> {
	line.find(prefix).map(|pos| {
		line[pos + prefix.len()..]
			.split_whitespace()
			.next()
			.unwrap_or("")
			.to_string()
	})
}

fn extract_quoted(line: &str, prefix: &str) -> Option<String> {
	let pos = line.find(prefix)?;
	let rest = &line[pos + prefix.len()..];
	if let Some(stripped) = rest.strip_prefix('"') {
		stripped.find('"').map(|end| stripped[..end].to_string())
	} else {
		rest.split_whitespace()
			.next()
			.map(|s| s.to_string())
	}
}

fn parse_iptables_rules() -> Result<Vec<FirewallRule>> {
	let output = std::process::Command::new("iptables-save")
		.output()
		.map_err(|e| MyceliumError::OsError {
			code: -1,
			message: format!("failed to run iptables-save: {e}"),
		})?;

	if !output.status.success() {
		return Ok(Vec::new());
	}

	let stdout = String::from_utf8_lossy(&output.stdout);
	let mut rules = Vec::new();
	let mut rule_id = 0u32;

	for line in stdout.lines() {
		if !line.starts_with("-A ") {
			continue;
		}

		rule_id += 1;
		let parts: Vec<&str> = line.split_whitespace().collect();

		let chain = parts.get(1).unwrap_or(&"").to_string();
		let mut protocol = None;
		let mut source = None;
		let mut destination = None;
		let mut port = None;
		let mut action = None;

		let mut i = 2;
		while i < parts.len() {
			match parts[i] {
				"-p" => {
					protocol = parts.get(i + 1).map(|s| s.to_string());
					i += 2;
				}
				"-s" => {
					source = parts.get(i + 1).map(|s| s.to_string());
					i += 2;
				}
				"-d" => {
					destination = parts.get(i + 1).map(|s| s.to_string());
					i += 2;
				}
				"--dport" => {
					port = parts.get(i + 1).and_then(|s| s.parse().ok());
					i += 2;
				}
				"-j" => {
					action = parts.get(i + 1).map(|s| match *s {
						"ACCEPT" => FirewallAction::Accept,
						"DROP" => FirewallAction::Drop,
						"REJECT" => FirewallAction::Reject,
						"LOG" => FirewallAction::Log,
						_ => FirewallAction::Accept,
					});
					i += 2;
				}
				_ => i += 1,
			}
		}

		if let Some(act) = action {
			rules.push(FirewallRule {
				id: rule_id.to_string(),
				chain,
				protocol,
				source,
				destination,
				port,
				action: act,
				comment: None,
			});
		}
	}

	Ok(rules)
}
