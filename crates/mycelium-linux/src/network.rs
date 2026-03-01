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

const VALID_PROTOCOLS: &[&str] = &[
	"tcp", "udp", "icmp", "icmpv6", "sctp", "dccp", "esp", "ah", "gre",
];
const MAX_COMMENT_LEN: usize = 256;

/// Validate a firewall chain name: alphanumeric, underscore, hyphen only.
fn validate_chain(chain: &str) -> Result<()> {
	if chain.is_empty()
		|| !chain.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
	{
		return Err(MyceliumError::ParseError(format!(
			"invalid chain name: {chain}"
		)));
	}
	Ok(())
}

/// Validate a protocol name against the allowlist.
fn validate_protocol(proto: &str) -> Result<()> {
	if !VALID_PROTOCOLS.contains(&proto.to_lowercase().as_str()) {
		return Err(MyceliumError::ParseError(format!(
			"invalid protocol: {proto} (allowed: {})",
			VALID_PROTOCOLS.join(", ")
		)));
	}
	Ok(())
}

/// Validate an IP address or CIDR notation.
fn validate_address(addr: &str) -> Result<()> {
	// Strip optional CIDR suffix
	let (ip_part, cidr) = if let Some((ip, prefix)) = addr.split_once('/') {
		(ip, Some(prefix))
	} else {
		(addr, None)
	};

	// Must be a valid IPv4 or IPv6 address
	if ip_part.parse::<std::net::IpAddr>().is_err() {
		return Err(MyceliumError::ParseError(format!(
			"invalid IP address: {addr}"
		)));
	}

	// CIDR prefix must be numeric and in range
	if let Some(prefix) = cidr {
		let bits: u8 = prefix.parse().map_err(|_| {
			MyceliumError::ParseError(format!("invalid CIDR prefix: {addr}"))
		})?;
		let max = if ip_part.contains(':') { 128 } else { 32 };
		if bits > max {
			return Err(MyceliumError::ParseError(format!(
				"CIDR prefix {bits} out of range for {addr}"
			)));
		}
	}

	Ok(())
}

/// Validate a firewall comment: no quotes or control characters.
fn validate_comment(comment: &str) -> Result<()> {
	if comment.len() > MAX_COMMENT_LEN {
		return Err(MyceliumError::ParseError(format!(
			"comment too long ({} chars, max {MAX_COMMENT_LEN})",
			comment.len()
		)));
	}
	if comment.contains('"') || comment.contains('\'') || comment.contains('\\') {
		return Err(MyceliumError::ParseError(
			"comment must not contain quotes or backslashes".into(),
		));
	}
	if comment.chars().any(|c| c.is_control()) {
		return Err(MyceliumError::ParseError(
			"comment must not contain control characters".into(),
		));
	}
	Ok(())
}

/// Validate all fields of a firewall rule before executing.
fn validate_firewall_rule(rule: &FirewallRule) -> Result<()> {
	validate_chain(&rule.chain)?;
	if let Some(proto) = &rule.protocol {
		validate_protocol(proto)?;
	}
	if let Some(src) = &rule.source {
		validate_address(src)?;
	}
	if let Some(dst) = &rule.destination {
		validate_address(dst)?;
	}
	if let Some(comment) = &rule.comment {
		validate_comment(comment)?;
	}
	Ok(())
}

pub fn add_firewall_rule(rule: &FirewallRule) -> Result<()> {
	validate_firewall_rule(rule)?;

	let nft_path = Path::new("/usr/sbin/nft");
	let ipt_path = Path::new("/usr/sbin/iptables");

	if nft_path.exists() {
		add_nft_rule(rule)
	} else if ipt_path.exists() {
		add_iptables_rule(rule)
	} else {
		Err(MyceliumError::Unsupported(
			"neither nft nor iptables found".into(),
		))
	}
}

fn add_nft_rule(rule: &FirewallRule) -> Result<()> {
	let chain = rule.chain.to_lowercase();
	let mut args = vec![
		"add".to_string(),
		"rule".to_string(),
		"inet".to_string(),
		"filter".to_string(),
		chain,
	];

	if let Some(proto) = &rule.protocol {
		args.extend(["ip".into(), "protocol".into(), proto.clone()]);
	}

	if let Some(src) = &rule.source {
		args.extend(["ip".into(), "saddr".into(), src.clone()]);
	}

	if let Some(dst) = &rule.destination {
		args.extend(["ip".into(), "daddr".into(), dst.clone()]);
	}

	if let Some(port) = rule.port {
		// Need protocol for dport; default to tcp if not specified
		let proto = rule.protocol.as_deref().unwrap_or("tcp");
		args.extend([proto.into(), "dport".into(), port.to_string()]);
	}

	let action = match rule.action {
		FirewallAction::Accept => "accept",
		FirewallAction::Drop => "drop",
		FirewallAction::Reject => "reject",
		FirewallAction::Log => "log",
	};
	args.push(action.into());

	if let Some(comment) = &rule.comment {
		// comment is already validated (no quotes/control chars)
		args.extend(["comment".into(), comment.clone()]);
	}

	let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
	let output = std::process::Command::new("nft")
		.args(&arg_refs)
		.output()
		.map_err(|e| MyceliumError::OsError {
			code: -1,
			message: format!("failed to run nft: {e}"),
		})?;

	if !output.status.success() {
		let stderr = String::from_utf8_lossy(&output.stderr);
		return Err(firewall_cmd_error("nft add rule", &stderr, &output));
	}

	Ok(())
}

fn add_iptables_rule(rule: &FirewallRule) -> Result<()> {
	let mut args = vec!["-A".to_string(), rule.chain.clone()];

	if let Some(proto) = &rule.protocol {
		args.extend(["-p".into(), proto.clone()]);
	}

	if let Some(src) = &rule.source {
		args.extend(["-s".into(), src.clone()]);
	}

	if let Some(dst) = &rule.destination {
		args.extend(["-d".into(), dst.clone()]);
	}

	if let Some(port) = rule.port {
		args.extend(["--dport".into(), port.to_string()]);
	}

	let action = match rule.action {
		FirewallAction::Accept => "ACCEPT",
		FirewallAction::Drop => "DROP",
		FirewallAction::Reject => "REJECT",
		FirewallAction::Log => "LOG",
	};
	args.extend(["-j".into(), action.into()]);

	if let Some(comment) = &rule.comment {
		args.extend([
			"-m".into(),
			"comment".into(),
			"--comment".into(),
			comment.clone(),
		]);
	}

	let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
	let output = std::process::Command::new("iptables")
		.args(&arg_refs)
		.output()
		.map_err(|e| MyceliumError::OsError {
			code: -1,
			message: format!("failed to run iptables: {e}"),
		})?;

	if !output.status.success() {
		let stderr = String::from_utf8_lossy(&output.stderr);
		return Err(firewall_cmd_error("iptables -A", &stderr, &output));
	}

	Ok(())
}

pub fn remove_firewall_rule(rule_id: &str) -> Result<()> {
	// Validate rule_id: must be numeric (nft handle) or chain:number (iptables)
	if rule_id.is_empty() {
		return Err(MyceliumError::ParseError("empty rule ID".into()));
	}
	if let Some((chain, num)) = rule_id.split_once(':') {
		validate_chain(chain)?;
		if num.parse::<u32>().is_err() {
			return Err(MyceliumError::ParseError(format!(
				"invalid iptables rule number: {num}"
			)));
		}
	} else if rule_id.parse::<u32>().is_err() {
		return Err(MyceliumError::ParseError(format!(
			"invalid rule ID: {rule_id} (expected numeric handle or chain:number)"
		)));
	}

	let nft_path = Path::new("/usr/sbin/nft");
	let ipt_path = Path::new("/usr/sbin/iptables");

	if nft_path.exists() {
		remove_nft_rule(rule_id)
	} else if ipt_path.exists() {
		remove_iptables_rule(rule_id)
	} else {
		Err(MyceliumError::Unsupported(
			"neither nft nor iptables found".into(),
		))
	}
}

/// Find the chain containing a given nft handle by parsing `nft -a list ruleset`.
fn find_nft_chain_for_handle(handle: &str) -> Result<Option<String>> {
	let output = std::process::Command::new("nft")
		.args(["list", "ruleset", "-a"])
		.output()
		.map_err(|e| MyceliumError::OsError {
			code: -1,
			message: format!("failed to run nft: {e}"),
		})?;

	if !output.status.success() {
		return Ok(None);
	}

	let stdout = String::from_utf8_lossy(&output.stdout);
	let mut current_chain = String::new();
	let handle_suffix = format!("handle {handle}");

	for line in stdout.lines() {
		let trimmed = line.trim();
		if trimmed.starts_with("chain ") {
			current_chain = trimmed
				.strip_prefix("chain ")
				.unwrap_or("")
				.trim_end_matches(" {")
				.trim()
				.to_string();
		} else if (trimmed.ends_with(&handle_suffix)
			|| trimmed.contains(&format!("handle {handle} ")))
			&& !current_chain.is_empty()
		{
			return Ok(Some(current_chain));
		}
	}

	Ok(None)
}

fn remove_nft_rule(rule_id: &str) -> Result<()> {
	let chain = find_nft_chain_for_handle(rule_id)?.ok_or_else(|| {
		MyceliumError::NotFound(format!("firewall rule handle {rule_id}"))
	})?;

	let output = std::process::Command::new("nft")
		.args([
			"delete", "rule", "inet", "filter", &chain, "handle", rule_id,
		])
		.output()
		.map_err(|e| MyceliumError::OsError {
			code: -1,
			message: format!("failed to run nft: {e}"),
		})?;

	if !output.status.success() {
		let stderr = String::from_utf8_lossy(&output.stderr);
		return Err(firewall_cmd_error("nft delete rule", &stderr, &output));
	}

	Ok(())
}

/// rule_id format: "<chain>:<line_number>" or just "<line_number>" (defaults to INPUT).
fn remove_iptables_rule(rule_id: &str) -> Result<()> {
	let (chain, num) = if let Some((c, n)) = rule_id.split_once(':') {
		(c.to_string(), n.to_string())
	} else {
		("INPUT".to_string(), rule_id.to_string())
	};

	let output = std::process::Command::new("iptables")
		.args(["-D", &chain, &num])
		.output()
		.map_err(|e| MyceliumError::OsError {
			code: -1,
			message: format!("failed to run iptables: {e}"),
		})?;

	if !output.status.success() {
		let stderr = String::from_utf8_lossy(&output.stderr);
		return Err(firewall_cmd_error("iptables -D", &stderr, &output));
	}

	Ok(())
}

fn firewall_cmd_error(
	cmd: &str,
	stderr: &str,
	output: &std::process::Output,
) -> MyceliumError {
	let stderr = stderr.trim();
	if stderr.contains("Permission denied")
		|| stderr.contains("Operation not permitted")
	{
		MyceliumError::PermissionDenied(format!(
			"{cmd} failed (run as root)"
		))
	} else {
		MyceliumError::OsError {
			code: output.status.code().unwrap_or(-1),
			message: format!("{cmd} failed: {stderr}"),
		}
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

#[cfg(test)]
mod tests {
	use super::*;

	// parse_hex_addr tests

	#[test]
	fn test_parse_hex_addr_ipv4_loopback() {
		// 127.0.0.1 little-endian = 0100007F
		let (addr, port) = parse_hex_addr("0100007F:0050");
		assert_eq!(addr, "127.0.0.1");
		assert_eq!(port, 80);
	}

	#[test]
	fn test_parse_hex_addr_ipv4_zeros() {
		let (addr, port) = parse_hex_addr("00000000:0000");
		assert_eq!(addr, "0.0.0.0");
		assert_eq!(port, 0);
	}

	#[test]
	fn test_parse_hex_addr_ipv4_real() {
		// 192.168.1.1 = C0.A8.01.01, little-endian = 0101A8C0
		let (addr, port) = parse_hex_addr("0101A8C0:01BB");
		assert_eq!(addr, "192.168.1.1");
		assert_eq!(port, 443);
	}

	#[test]
	fn test_parse_hex_addr_ipv6_loopback() {
		let (addr, port) = parse_hex_addr("00000000000000000000000001000000:0016");
		assert_eq!(addr, "::1");
		assert_eq!(port, 22);
	}

	#[test]
	fn test_parse_hex_addr_ipv6_full() {
		let (addr, _) = parse_hex_addr("00000000000000000000000000000000:0000");
		assert_eq!(addr, "::");
	}

	#[test]
	fn test_parse_hex_addr_malformed_no_colon() {
		let (addr, port) = parse_hex_addr("0100007F");
		assert_eq!(addr, "0.0.0.0");
		assert_eq!(port, 0);
	}

	#[test]
	fn test_parse_hex_addr_max_port() {
		let (_, port) = parse_hex_addr("00000000:FFFF");
		assert_eq!(port, 65535);
	}

	#[test]
	fn test_parse_hex_addr_odd_length_addr() {
		let (addr, port) = parse_hex_addr("0100:0050");
		assert_eq!(addr, "0.0.0.0");
		assert_eq!(port, 80);
	}

	// parse_tcp_state tests

	#[test]
	fn test_parse_tcp_state_established() {
		assert_eq!(parse_tcp_state(0x01), ConnectionState::Established);
	}

	#[test]
	fn test_parse_tcp_state_all_valid() {
		assert_eq!(parse_tcp_state(0x02), ConnectionState::SynSent);
		assert_eq!(parse_tcp_state(0x03), ConnectionState::SynRecv);
		assert_eq!(parse_tcp_state(0x04), ConnectionState::FinWait1);
		assert_eq!(parse_tcp_state(0x05), ConnectionState::FinWait2);
		assert_eq!(parse_tcp_state(0x06), ConnectionState::TimeWait);
		assert_eq!(parse_tcp_state(0x07), ConnectionState::Close);
		assert_eq!(parse_tcp_state(0x08), ConnectionState::CloseWait);
		assert_eq!(parse_tcp_state(0x09), ConnectionState::LastAck);
		assert_eq!(parse_tcp_state(0x0A), ConnectionState::Listen);
		assert_eq!(parse_tcp_state(0x0B), ConnectionState::Closing);
	}

	#[test]
	fn test_parse_tcp_state_unknown() {
		assert_eq!(parse_tcp_state(0x00), ConnectionState::Unknown);
		assert_eq!(parse_tcp_state(0x0C), ConnectionState::Unknown);
		assert_eq!(parse_tcp_state(0xFF), ConnectionState::Unknown);
	}

	// extract_word_after tests

	#[test]
	fn test_extract_word_after_found() {
		let line = "ip protocol tcp dport 80 accept";
		assert_eq!(
			extract_word_after(line, "ip protocol "),
			Some("tcp".to_string())
		);
	}

	#[test]
	fn test_extract_word_after_not_found() {
		let line = "ip daddr 10.0.0.1 accept";
		assert_eq!(extract_word_after(line, "ip protocol "), None);
	}

	#[test]
	fn test_extract_word_after_at_end() {
		let line = "ip protocol ";
		assert_eq!(
			extract_word_after(line, "ip protocol "),
			Some(String::new())
		);
	}

	#[test]
	fn test_extract_word_after_multiple_matches() {
		let line = "ip saddr 10.0.0.1 ip saddr 10.0.0.2";
		assert_eq!(
			extract_word_after(line, "ip saddr "),
			Some("10.0.0.1".to_string())
		);
	}

	// extract_quoted tests

	#[test]
	fn test_extract_quoted_with_quotes() {
		let line = r#"comment "allow ssh" accept"#;
		assert_eq!(
			extract_quoted(line, "comment "),
			Some("allow ssh".to_string())
		);
	}

	#[test]
	fn test_extract_quoted_without_quotes() {
		let line = "comment allow_ssh accept";
		assert_eq!(
			extract_quoted(line, "comment "),
			Some("allow_ssh".to_string())
		);
	}

	#[test]
	fn test_extract_quoted_not_found() {
		let line = "ip protocol tcp accept";
		assert_eq!(extract_quoted(line, "comment "), None);
	}

	#[test]
	fn test_extract_quoted_empty_quotes() {
		let line = r#"comment "" accept"#;
		assert_eq!(extract_quoted(line, "comment "), Some(String::new()));
	}
}
