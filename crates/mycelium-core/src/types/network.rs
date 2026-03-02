//! Network-related types.

/// A network interface.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NetworkInterface {
	pub name: String,
	pub mac_address: Option<String>,
	pub ipv4_addresses: Vec<String>,
	pub ipv6_addresses: Vec<String>,
	pub mtu: u32,
	pub speed_mbps: Option<u64>,
	pub state: InterfaceState,
	pub rx_bytes: u64,
	pub tx_bytes: u64,
	pub rx_packets: u64,
	pub tx_packets: u64,
	pub rx_errors: u64,
	pub tx_errors: u64,
}

/// Interface operational state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum InterfaceState {
	Up,
	Down,
	Unknown,
}

/// A network connection.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Connection {
	pub protocol: Protocol,
	pub local_address: String,
	pub local_port: u16,
	pub remote_address: String,
	pub remote_port: u16,
	pub state: ConnectionState,
	pub pid: Option<u32>,
	pub process_name: Option<String>,
}

/// Transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Protocol {
	Tcp,
	Tcp6,
	Udp,
	Udp6,
}

/// TCP connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ConnectionState {
	Established,
	SynSent,
	SynRecv,
	FinWait1,
	FinWait2,
	TimeWait,
	Close,
	CloseWait,
	LastAck,
	Listen,
	Closing,
	Unknown,
}

/// A routing table entry.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Route {
	pub destination: String,
	pub gateway: String,
	pub netmask: String,
	pub interface: String,
	pub metric: u32,
	pub flags: String,
}

/// An open port with its owning process.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OpenPort {
	pub protocol: Protocol,
	pub address: String,
	pub port: u16,
	pub pid: Option<u32>,
	pub process_name: Option<String>,
}

/// A firewall rule.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FirewallRule {
	pub id: String,
	pub chain: String,
	pub protocol: Option<String>,
	pub source: Option<String>,
	pub destination: Option<String>,
	pub port: Option<u16>,
	pub action: FirewallAction,
	pub comment: Option<String>,
}

/// Firewall rule action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum FirewallAction {
	Accept,
	Drop,
	Reject,
	Log,
}
