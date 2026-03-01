use clap::Subcommand;
use mycelium_core::platform::Platform;
use mycelium_core::types::*;

use crate::output::*;

#[derive(Subcommand)]
pub enum NetworkCmd {
	/// List network interfaces
	Interfaces,
	/// List active connections
	Connections,
	/// List routing table
	Routes,
	/// List open (listening) ports
	Ports,
	/// List firewall rules
	Firewall,
}

impl NetworkCmd {
	pub fn run(&self, platform: &dyn Platform, format: OutputFormat) {
		match self {
			Self::Interfaces => match platform.list_interfaces() {
				Ok(ifaces) => print_list(&ifaces, format),
				Err(e) => eprintln!("error: {e}"),
			},
			Self::Connections => match platform.list_connections() {
				Ok(conns) => print_list(&conns, format),
				Err(e) => eprintln!("error: {e}"),
			},
			Self::Routes => match platform.list_routes() {
				Ok(routes) => print_list(&routes, format),
				Err(e) => eprintln!("error: {e}"),
			},
			Self::Ports => match platform.list_open_ports() {
				Ok(ports) => print_list(&ports, format),
				Err(e) => eprintln!("error: {e}"),
			},
			Self::Firewall => match platform.list_firewall_rules() {
				Ok(rules) => print_list(&rules, format),
				Err(e) => eprintln!("error: {e}"),
			},
		}
	}
}

impl TableDisplay for NetworkInterface {
	fn print_header() {
		println!(
			"{:<15} {:<18} {:<8} {:<18} {:>12} {:>12}",
			"NAME", "MAC", "STATE", "IPv4", "RX", "TX"
		);
	}

	fn print_row(&self) {
		let state = format!("{:?}", self.state);
		let ipv4 = self.ipv4_addresses.first().cloned().unwrap_or_default();
		println!(
			"{:<15} {:<18} {:<8} {:<18} {:>12} {:>12}",
			self.name,
			self.mac_address.as_deref().unwrap_or("-"),
			state,
			ipv4,
			human_bytes(self.rx_bytes),
			human_bytes(self.tx_bytes),
		);
	}
}

impl TableDisplay for Connection {
	fn print_header() {
		println!(
			"{:<6} {:<25} {:<25} {:<12} {:>7} PROCESS",
			"PROTO", "LOCAL", "REMOTE", "STATE", "PID"
		);
	}

	fn print_row(&self) {
		let proto = format!("{:?}", self.protocol);
		let local = format!("{}:{}", self.local_address, self.local_port);
		let remote = format!("{}:{}", self.remote_address, self.remote_port);
		let state = format!("{:?}", self.state);
		println!(
			"{:<6} {:<25} {:<25} {:<12} {:>7} {}",
			proto,
			truncate(&local, 25),
			truncate(&remote, 25),
			state,
			self.pid.map(|p| p.to_string()).unwrap_or_default(),
			self.process_name.as_deref().unwrap_or("-"),
		);
	}
}

impl TableDisplay for Route {
	fn print_header() {
		println!(
			"{:<18} {:<18} {:<18} {:<10} {:>6}",
			"DESTINATION", "GATEWAY", "NETMASK", "IFACE", "METRIC"
		);
	}

	fn print_row(&self) {
		println!(
			"{:<18} {:<18} {:<18} {:<10} {:>6}",
			self.destination, self.gateway, self.netmask, self.interface, self.metric
		);
	}
}

impl TableDisplay for OpenPort {
	fn print_header() {
		println!(
			"{:<6} {:<25} {:>7} PROCESS",
			"PROTO", "ADDRESS", "PID"
		);
	}

	fn print_row(&self) {
		let proto = format!("{:?}", self.protocol);
		let addr = format!("{}:{}", self.address, self.port);
		println!(
			"{:<6} {:<25} {:>7} {}",
			proto,
			addr,
			self.pid.map(|p| p.to_string()).unwrap_or_default(),
			self.process_name.as_deref().unwrap_or("-"),
		);
	}
}

impl TableDisplay for FirewallRule {
	fn print_header() {
		println!(
			"{:<6} {:<12} {:<8} {:<18} {:<18} {:>6} {:<8}",
			"ID", "CHAIN", "PROTO", "SOURCE", "DEST", "PORT", "ACTION"
		);
	}

	fn print_row(&self) {
		let action = format!("{:?}", self.action);
		println!(
			"{:<6} {:<12} {:<8} {:<18} {:<18} {:>6} {:<8}",
			self.id,
			self.chain,
			self.protocol.as_deref().unwrap_or("-"),
			self.source.as_deref().unwrap_or("*"),
			self.destination.as_deref().unwrap_or("*"),
			self.port.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
			action,
		);
	}
}
