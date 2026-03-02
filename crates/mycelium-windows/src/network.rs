//! Network information via sysinfo, WinAPI, WMI, and netsh.

use std::collections::HashMap;
use std::ffi::c_void;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;

use sysinfo::{Networks, ProcessRefreshKind, RefreshKind, System};
use windows::Win32::NetworkManagement::IpHelper::{
	ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToNameW, FreeMibTable,
	GetAdaptersAddresses, GetExtendedTcpTable, GetExtendedUdpTable, GetIpForwardTable2,
	GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
	IP_ADAPTER_ADDRESSES_LH, IP_ADDRESS_PREFIX, MIB_IPFORWARD_TABLE2,
	MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID,
	MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
	MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
	UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{
	ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_INET,
};
use wmi::{COMLibrary, WMIConnection};

use mycelium_core::error::{MyceliumError, Result};
use mycelium_core::types::{
	Connection, ConnectionState, FirewallAction, FirewallRule, InterfaceState, NetworkInterface,
	OpenPort, Protocol, Route,
};

/// Build a map from adapter friendly name to MTU using `GetAdaptersAddresses`.
fn get_adapter_mtus() -> HashMap<String, u32> {
	let mut map = HashMap::new();
	let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_MULTICAST;
	let mut size = 0u32;

	// First call: determine required buffer size
	unsafe {
		GetAdaptersAddresses(0u32, flags, None, None, &mut size);
	}

	if size == 0 {
		return map;
	}

	let mut buffer = vec![0u8; size as usize];
	let adapter_ptr = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

	let ret = unsafe { GetAdaptersAddresses(0u32, flags, None, Some(adapter_ptr), &mut size) };

	if ret != 0 {
		return map;
	}

	// Walk the linked list
	let mut current = adapter_ptr;
	while !current.is_null() {
		unsafe {
			let adapter = &*current;
			if let Ok(name) = adapter.FriendlyName.to_string() {
				map.insert(name, adapter.Mtu);
			}
			current = adapter.Next;
		}
	}

	map
}

#[derive(serde::Deserialize)]
#[allow(non_snake_case)]
struct WmiNetworkAdapter {
	Name: Option<String>,
	Speed: Option<u64>,
}

/// Query WMI `Win32_NetworkAdapter` to get adapter speeds in Mbps.
fn get_adapter_speeds() -> HashMap<String, u64> {
	let mut map = HashMap::new();

	let com = match COMLibrary::new() {
		Ok(c) => c,
		Err(_) => return map,
	};
	let wmi = match WMIConnection::new(com) {
		Ok(w) => w,
		Err(_) => return map,
	};

	let results: Vec<WmiNetworkAdapter> = wmi
		.raw_query("SELECT Name, Speed FROM Win32_NetworkAdapter WHERE Speed IS NOT NULL")
		.unwrap_or_default();

	for adapter in results {
		if let (Some(name), Some(speed_bps)) = (adapter.Name, adapter.Speed)
			&& speed_bps > 0
		{
			map.insert(name, speed_bps / 1_000_000);
		}
	}

	map
}

pub fn list_interfaces() -> Result<Vec<NetworkInterface>> {
	let networks = Networks::new_with_refreshed_list();
	let mtu_map = get_adapter_mtus();
	let speed_map = get_adapter_speeds();

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
				mtu: mtu_map.get(name.as_str()).copied().unwrap_or(0),
				speed_mbps: speed_map.get(name.as_str()).copied(),
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

/// Build a map of PID → process name using sysinfo.
fn build_pid_name_map() -> HashMap<u32, String> {
	let sys = System::new_with_specifics(
		RefreshKind::nothing().with_processes(ProcessRefreshKind::nothing()),
	);
	sys.processes()
		.iter()
		.map(|(pid, proc)| {
			(
				pid.as_u32(),
				proc.name().to_string_lossy().into_owned(),
			)
		})
		.collect()
}

/// Convert a Windows TCP state DWORD to a `ConnectionState`.
fn tcp_state_from_dword(state: u32) -> ConnectionState {
	match state {
		1 => ConnectionState::Close,
		2 => ConnectionState::Listen,
		3 => ConnectionState::SynSent,
		4 => ConnectionState::SynRecv,
		5 => ConnectionState::Established,
		6 => ConnectionState::FinWait1,
		7 => ConnectionState::FinWait2,
		8 => ConnectionState::CloseWait,
		9 => ConnectionState::Closing,
		10 => ConnectionState::LastAck,
		11 => ConnectionState::TimeWait,
		12 => ConnectionState::Close,
		_ => ConnectionState::Unknown,
	}
}

/// Get IPv4 TCP connections using `GetExtendedTcpTable`.
fn get_tcp4_connections(pid_names: &HashMap<u32, String>) -> Vec<Connection> {
	let mut size = 0u32;
	unsafe {
		GetExtendedTcpTable(None, &mut size, false, AF_INET.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0);
	}
	if size == 0 {
		return Vec::new();
	}

	let mut buffer = vec![0u8; size as usize];
	let ret = unsafe {
		GetExtendedTcpTable(
			Some(buffer.as_mut_ptr() as *mut c_void),
			&mut size,
			false,
			AF_INET.0 as u32,
			TCP_TABLE_OWNER_PID_ALL,
			0,
		)
	};
	if ret != 0 {
		return Vec::new();
	}

	let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
	let rows = unsafe {
		std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize)
	};

	rows.iter().map(|row: &MIB_TCPROW_OWNER_PID| {
		let local_addr = Ipv4Addr::from(u32::from_be(row.dwLocalAddr));
		let remote_addr = Ipv4Addr::from(u32::from_be(row.dwRemoteAddr));
		let local_port = u16::from_be(row.dwLocalPort as u16);
		let remote_port = u16::from_be(row.dwRemotePort as u16);
		let pid = row.dwOwningPid;
		let process_name = pid_names.get(&pid).cloned();

		Connection {
			protocol: Protocol::Tcp,
			local_address: local_addr.to_string(),
			local_port,
			remote_address: remote_addr.to_string(),
			remote_port,
			state: tcp_state_from_dword(row.dwState),
			pid: Some(pid),
			process_name,
		}
	}).collect()
}

/// Get IPv6 TCP connections using `GetExtendedTcpTable`.
fn get_tcp6_connections(pid_names: &HashMap<u32, String>) -> Vec<Connection> {
	let mut size = 0u32;
	unsafe {
		GetExtendedTcpTable(None, &mut size, false, AF_INET6.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0);
	}
	if size == 0 {
		return Vec::new();
	}

	let mut buffer = vec![0u8; size as usize];
	let ret = unsafe {
		GetExtendedTcpTable(
			Some(buffer.as_mut_ptr() as *mut c_void),
			&mut size,
			false,
			AF_INET6.0 as u32,
			TCP_TABLE_OWNER_PID_ALL,
			0,
		)
	};
	if ret != 0 {
		return Vec::new();
	}

	let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
	let rows = unsafe {
		std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize)
	};

	rows.iter().map(|row: &MIB_TCP6ROW_OWNER_PID| {
		let local_addr = Ipv6Addr::from(row.ucLocalAddr);
		let remote_addr = Ipv6Addr::from(row.ucRemoteAddr);
		let local_port = u16::from_be(row.dwLocalPort as u16);
		let remote_port = u16::from_be(row.dwRemotePort as u16);
		let pid = row.dwOwningPid;
		let process_name = pid_names.get(&pid).cloned();

		Connection {
			protocol: Protocol::Tcp6,
			local_address: local_addr.to_string(),
			local_port,
			remote_address: remote_addr.to_string(),
			remote_port,
			state: tcp_state_from_dword(row.dwState),
			pid: Some(pid),
			process_name,
		}
	}).collect()
}

/// Get IPv4 UDP connections using `GetExtendedUdpTable`.
fn get_udp4_connections(pid_names: &HashMap<u32, String>) -> Vec<Connection> {
	let mut size = 0u32;
	unsafe {
		GetExtendedUdpTable(None, &mut size, false, AF_INET.0 as u32, UDP_TABLE_OWNER_PID, 0);
	}
	if size == 0 {
		return Vec::new();
	}

	let mut buffer = vec![0u8; size as usize];
	let ret = unsafe {
		GetExtendedUdpTable(
			Some(buffer.as_mut_ptr() as *mut c_void),
			&mut size,
			false,
			AF_INET.0 as u32,
			UDP_TABLE_OWNER_PID,
			0,
		)
	};
	if ret != 0 {
		return Vec::new();
	}

	let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
	let rows = unsafe {
		std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize)
	};

	rows.iter().map(|row: &MIB_UDPROW_OWNER_PID| {
		let local_addr = Ipv4Addr::from(u32::from_be(row.dwLocalAddr));
		let local_port = u16::from_be(row.dwLocalPort as u16);
		let pid = row.dwOwningPid;
		let process_name = pid_names.get(&pid).cloned();

		Connection {
			protocol: Protocol::Udp,
			local_address: local_addr.to_string(),
			local_port,
			remote_address: "*".to_string(),
			remote_port: 0,
			state: ConnectionState::Unknown,
			pid: Some(pid),
			process_name,
		}
	}).collect()
}

/// Get IPv6 UDP connections using `GetExtendedUdpTable`.
fn get_udp6_connections(pid_names: &HashMap<u32, String>) -> Vec<Connection> {
	let mut size = 0u32;
	unsafe {
		GetExtendedUdpTable(None, &mut size, false, AF_INET6.0 as u32, UDP_TABLE_OWNER_PID, 0);
	}
	if size == 0 {
		return Vec::new();
	}

	let mut buffer = vec![0u8; size as usize];
	let ret = unsafe {
		GetExtendedUdpTable(
			Some(buffer.as_mut_ptr() as *mut c_void),
			&mut size,
			false,
			AF_INET6.0 as u32,
			UDP_TABLE_OWNER_PID,
			0,
		)
	};
	if ret != 0 {
		return Vec::new();
	}

	let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID) };
	let rows = unsafe {
		std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize)
	};

	rows.iter().map(|row: &MIB_UDP6ROW_OWNER_PID| {
		let local_addr = Ipv6Addr::from(row.ucLocalAddr);
		let local_port = u16::from_be(row.dwLocalPort as u16);
		let pid = row.dwOwningPid;
		let process_name = pid_names.get(&pid).cloned();

		Connection {
			protocol: Protocol::Udp6,
			local_address: local_addr.to_string(),
			local_port,
			remote_address: "*".to_string(),
			remote_port: 0,
			state: ConnectionState::Unknown,
			pid: Some(pid),
			process_name,
		}
	}).collect()
}

/// List all active TCP/UDP connections using Win32 IP helper APIs.
pub fn list_connections() -> Result<Vec<Connection>> {
	let pid_names = build_pid_name_map();

	let mut connections = Vec::new();
	connections.extend(get_tcp4_connections(&pid_names));
	connections.extend(get_tcp6_connections(&pid_names));
	connections.extend(get_udp4_connections(&pid_names));
	connections.extend(get_udp6_connections(&pid_names));

	Ok(connections)
}

/// Get the interface name from an interface index.
fn interface_name_from_index(index: u32) -> String {
	unsafe {
		let mut luid = std::mem::zeroed();
		if ConvertInterfaceIndexToLuid(index, &mut luid).is_err() {
			return format!("if{index}");
		}
		let mut name_buf = [0u16; 256];
		if ConvertInterfaceLuidToNameW(&luid, &mut name_buf).is_err() {
			return format!("if{index}");
		}
		let len = name_buf.iter().position(|&c| c == 0).unwrap_or(name_buf.len());
		String::from_utf16_lossy(&name_buf[..len])
	}
}

/// Convert a route protocol number to a flags string.
fn route_protocol_to_flags(protocol: i32) -> String {
	match protocol {
		1 => "other".to_string(),
		2 => "local".to_string(),
		3 => "static".to_string(),
		4 => "icmp".to_string(),
		_ => format!("proto{protocol}"),
	}
}

/// Format a `SOCKADDR_INET` as an IP address string.
fn format_sockaddr_inet(sa: &SOCKADDR_INET) -> String {
	unsafe {
		if sa.si_family == AF_INET {
			let addr = Ipv4Addr::from(sa.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes());
			addr.to_string()
		} else if sa.si_family == AF_INET6 {
			let addr = Ipv6Addr::from(sa.Ipv6.sin6_addr.u.Byte);
			addr.to_string()
		} else {
			String::from("0.0.0.0")
		}
	}
}

/// Format an `IP_ADDRESS_PREFIX` as (destination, netmask) strings.
fn format_prefix(prefix: &IP_ADDRESS_PREFIX) -> (String, String) {
	let prefix_len = prefix.PrefixLength;
	let addr_str = format_sockaddr_inet(&prefix.Prefix);

	unsafe {
		if prefix.Prefix.si_family == AF_INET {
			// Convert prefix length to dotted-quad netmask
			let mask: u32 = if prefix_len == 0 {
				0
			} else {
				!0u32 << (32 - prefix_len)
			};
			let netmask = Ipv4Addr::from(mask.to_be_bytes());
			(addr_str, netmask.to_string())
		} else {
			// IPv6: use addr/prefix_len format
			let destination = format!("{addr_str}/{prefix_len}");
			let netmask = format!("/{prefix_len}");
			(destination, netmask)
		}
	}
}

/// List routing table entries using `GetIpForwardTable2`.
pub fn list_routes() -> Result<Vec<Route>> {
	let mut table_ptr: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();

	let ret = unsafe { GetIpForwardTable2(ADDRESS_FAMILY(AF_UNSPEC.0), &mut table_ptr) };

	if ret.is_err() || table_ptr.is_null() {
		return Ok(Vec::new());
	}

	let mut routes = Vec::new();

	unsafe {
		let table = &*table_ptr;
		let rows = std::slice::from_raw_parts(table.Table.as_ptr(), table.NumEntries as usize);

		for row in rows {
			let (destination, netmask) = format_prefix(&row.DestinationPrefix);
			let gateway = format_sockaddr_inet(&row.NextHop);
			let interface = interface_name_from_index(row.InterfaceIndex);
			let flags = route_protocol_to_flags(row.Protocol.0);

			routes.push(Route {
				destination,
				netmask,
				gateway,
				interface,
				metric: row.Metric,
				flags,
			});
		}

		FreeMibTable(table_ptr as *const c_void);
	}

	Ok(routes)
}

pub fn list_open_ports() -> Result<Vec<OpenPort>> {
	let connections = list_connections()?;

	let ports = connections
		.into_iter()
		.filter(|c| {
			c.state == ConnectionState::Listen
				|| c.protocol == Protocol::Udp
				|| c.protocol == Protocol::Udp6
		})
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
#[allow(non_snake_case, dead_code)]
struct WmiFirewallRule {
	InstanceID: Option<String>,
	DisplayName: Option<String>,
	Direction: Option<u16>,
	Protocol: Option<u16>,
	Action: Option<u16>,
	Enabled: Option<u16>,
	Description: Option<String>,
}

#[derive(serde::Deserialize)]
#[allow(non_snake_case, dead_code)]
struct WmiFirewallPortFilter {
	InstanceID: Option<String>,
	LocalPort: Option<String>,
	RemotePort: Option<String>,
	Protocol: Option<String>,
}

#[derive(serde::Deserialize)]
#[allow(non_snake_case)]
struct WmiFirewallAddressFilter {
	InstanceID: Option<String>,
	LocalAddress: Option<String>,
	RemoteAddress: Option<String>,
}

/// Parse the first port number from a WMI port string (may be "80", "80,443", or "*").
fn parse_first_port(s: &str) -> Option<u16> {
	let s = s.trim();
	if s.is_empty() || s == "*" || s.eq_ignore_ascii_case("Any") {
		return None;
	}
	// Take the first port if comma-separated
	s.split(',')
		.next()
		.and_then(|p| p.trim().parse().ok())
}

/// Normalize a firewall address: "*" and "Any" become None.
fn normalize_address(s: &str) -> Option<String> {
	let s = s.trim();
	if s.is_empty() || s == "*" || s.eq_ignore_ascii_case("Any") || s == "LocalSubnet" {
		None
	} else {
		Some(s.to_string())
	}
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

	// Query port and address filters
	let port_filters: Vec<WmiFirewallPortFilter> = wmi
		.raw_query("SELECT InstanceID, LocalPort, RemotePort, Protocol FROM MSFT_NetFirewallPortFilter")
		.unwrap_or_default();

	let addr_filters: Vec<WmiFirewallAddressFilter> = wmi
		.raw_query("SELECT InstanceID, LocalAddress, RemoteAddress FROM MSFT_NetFirewallAddressFilter")
		.unwrap_or_default();

	// Build lookup maps by InstanceID
	let port_map: HashMap<String, &WmiFirewallPortFilter> = port_filters
		.iter()
		.filter_map(|f| f.InstanceID.as_ref().map(|id| (id.clone(), f)))
		.collect();

	let addr_map: HashMap<String, &WmiFirewallAddressFilter> = addr_filters
		.iter()
		.filter_map(|f| f.InstanceID.as_ref().map(|id| (id.clone(), f)))
		.collect();

	let rules = results
		.into_iter()
		.map(|r| {
			let instance_id = r.InstanceID.clone().unwrap_or_default();

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

			// Get protocol from rule-level first, then port filter
			let mut proto = r.Protocol.map(|p| match p {
				6 => "tcp".to_string(),
				17 => "udp".to_string(),
				1 => "icmp".to_string(),
				_ => p.to_string(),
			});

			let mut port = None;
			let mut source = None;
			let mut destination = None;

			// Look up port filter
			if let Some(pf) = port_map.get(&instance_id) {
				if proto.is_none()
					&& let Some(ref p) = pf.Protocol
				{
					let p = p.trim();
					if !p.is_empty() && p != "*" {
						proto = Some(p.to_lowercase());
					}
				}
				if let Some(ref lp) = pf.LocalPort {
					port = parse_first_port(lp);
				}
			}

			// Look up address filter
			if let Some(af) = addr_map.get(&instance_id) {
				if let Some(ref la) = af.LocalAddress {
					destination = normalize_address(la);
				}
				if let Some(ref ra) = af.RemoteAddress {
					source = normalize_address(ra);
				}
			}

			FirewallRule {
				id: instance_id,
				chain: direction.to_string(),
				protocol: proto,
				source,
				destination,
				port,
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

#[cfg(test)]
mod tests {
	use super::*;

	// -- tcp_state_from_dword --

	#[test]
	fn test_tcp_state_listen() {
		assert_eq!(tcp_state_from_dword(2), ConnectionState::Listen);
	}

	#[test]
	fn test_tcp_state_established() {
		assert_eq!(tcp_state_from_dword(5), ConnectionState::Established);
	}

	#[test]
	fn test_tcp_state_unknown() {
		assert_eq!(tcp_state_from_dword(99), ConnectionState::Unknown);
	}

	// -- route_protocol_to_flags --

	#[test]
	fn test_route_protocol_other() {
		assert_eq!(route_protocol_to_flags(1), "other");
	}

	#[test]
	fn test_route_protocol_local() {
		assert_eq!(route_protocol_to_flags(2), "local");
	}

	#[test]
	fn test_route_protocol_static() {
		assert_eq!(route_protocol_to_flags(3), "static");
	}

	#[test]
	fn test_route_protocol_icmp() {
		assert_eq!(route_protocol_to_flags(4), "icmp");
	}

	#[test]
	fn test_route_protocol_unknown() {
		assert_eq!(route_protocol_to_flags(13), "proto13");
	}

	// -- parse_first_port --

	#[test]
	fn test_parse_first_port_single() {
		assert_eq!(parse_first_port("80"), Some(80));
	}

	#[test]
	fn test_parse_first_port_comma_separated() {
		assert_eq!(parse_first_port("80,443,8080"), Some(80));
	}

	#[test]
	fn test_parse_first_port_star() {
		assert_eq!(parse_first_port("*"), None);
	}

	#[test]
	fn test_parse_first_port_any() {
		assert_eq!(parse_first_port("Any"), None);
	}

	#[test]
	fn test_parse_first_port_empty() {
		assert_eq!(parse_first_port(""), None);
	}

	#[test]
	fn test_parse_first_port_whitespace() {
		assert_eq!(parse_first_port("  443  "), Some(443));
	}

	#[test]
	fn test_parse_first_port_invalid() {
		assert_eq!(parse_first_port("abc"), None);
	}

	#[test]
	fn test_parse_first_port_max() {
		assert_eq!(parse_first_port("65535"), Some(65535));
	}

	// -- normalize_address --

	#[test]
	fn test_normalize_address_real_ip() {
		assert_eq!(normalize_address("192.168.1.1"), Some("192.168.1.1".to_string()));
	}

	#[test]
	fn test_normalize_address_star() {
		assert_eq!(normalize_address("*"), None);
	}

	#[test]
	fn test_normalize_address_any() {
		assert_eq!(normalize_address("Any"), None);
	}

	#[test]
	fn test_normalize_address_local_subnet() {
		assert_eq!(normalize_address("LocalSubnet"), None);
	}

	#[test]
	fn test_normalize_address_empty() {
		assert_eq!(normalize_address(""), None);
	}

	#[test]
	fn test_normalize_address_cidr() {
		assert_eq!(normalize_address("10.0.0.0/8"), Some("10.0.0.0/8".to_string()));
	}

	#[test]
	fn test_normalize_address_whitespace() {
		assert_eq!(normalize_address("  192.168.1.0/24  "), Some("192.168.1.0/24".to_string()));
	}
}
