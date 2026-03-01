# Type Reference

All types are defined in `mycelium-core` under `src/types/`. Every struct and enum derives `Debug` and `Clone`. When the `serde` feature is enabled, they also derive `Serialize` and `Deserialize`.

```rust
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
```

## Process Types

**Module:** `types::process`

### ProcessInfo

```rust
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub state: ProcessState,
    pub user: String,
    pub uid: u32,
    pub threads: u32,
    pub cpu_percent: f64,
    pub memory_bytes: u64,
    pub command: String,
    pub start_time: u64,           // Unix timestamp
}
```

### ProcessState

```rust
pub enum ProcessState {
    Running,
    Sleeping,
    DiskSleep,
    Stopped,
    Zombie,
    Dead,
    Unknown,
}
```

Also derives `Copy`, `PartialEq`, `Eq`.

### ProcessResource

```rust
pub struct ProcessResource {
    pub pid: u32,
    pub cpu_percent: f64,
    pub memory_bytes: u64,
    pub memory_percent: f64,
    pub virtual_memory_bytes: u64,
    pub open_fds: u32,
    pub threads: u32,
    pub read_bytes: u64,
    pub write_bytes: u64,
}
```

### ProcessMemory

```rust
pub struct ProcessMemory {
    pub pid: u32,
    pub rss_bytes: u64,            // Resident Set Size
    pub virtual_bytes: u64,        // Virtual memory
    pub shared_bytes: u64,         // Shared memory
    pub text_bytes: u64,           // Text (code) segment
    pub data_bytes: u64,           // Data + stack segment
}
```

### Signal

```rust
pub enum Signal {
    Term,
    Kill,
    Hup,
    Int,
    Usr1,
    Usr2,
    Stop,
    Cont,
}
```

Also derives `Copy`, `PartialEq`, `Eq`.

---

## Memory Types

**Module:** `types::memory`

### MemoryInfo

```rust
pub struct MemoryInfo {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub used_bytes: u64,           // total - available
    pub free_bytes: u64,
    pub buffers_bytes: u64,
    pub cached_bytes: u64,
    pub swap: SwapInfo,
}
```

### SwapInfo

```rust
pub struct SwapInfo {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
}
```

---

## Network Types

**Module:** `types::network`

### NetworkInterface

```rust
pub struct NetworkInterface {
    pub name: String,
    pub mac_address: Option<String>,
    pub ipv4_addresses: Vec<String>,
    pub ipv6_addresses: Vec<String>,
    pub mtu: u32,
    pub state: InterfaceState,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
}
```

### InterfaceState

```rust
pub enum InterfaceState {
    Up,
    Down,
    Unknown,
}
```

Also derives `Copy`, `PartialEq`, `Eq`.

### Connection

```rust
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
```

### Protocol

```rust
pub enum Protocol {
    Tcp,
    Tcp6,
    Udp,
    Udp6,
}
```

Also derives `Copy`, `PartialEq`, `Eq`.

### ConnectionState

```rust
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
```

Also derives `Copy`, `PartialEq`, `Eq`.

### Route

```rust
pub struct Route {
    pub destination: String,
    pub gateway: String,
    pub netmask: String,
    pub interface: String,
    pub metric: u32,
    pub flags: String,
}
```

### OpenPort

```rust
pub struct OpenPort {
    pub protocol: Protocol,
    pub address: String,
    pub port: u16,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
}
```

### FirewallRule

```rust
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
```

### FirewallAction

```rust
pub enum FirewallAction {
    Accept,
    Drop,
    Reject,
    Log,
}
```

Also derives `Copy`, `PartialEq`, `Eq`.

---

## Storage Types

**Module:** `types::storage`

### DiskInfo

```rust
pub struct DiskInfo {
    pub name: String,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub size_bytes: u64,
    pub removable: bool,
    pub rotational: bool,
}
```

### Partition

```rust
pub struct Partition {
    pub name: String,
    pub parent_disk: String,
    pub size_bytes: u64,
    pub filesystem: Option<String>,
    pub mount_point: Option<String>,
    pub label: Option<String>,
    pub uuid: Option<String>,
}
```

### MountPoint

```rust
pub struct MountPoint {
    pub device: String,
    pub mount_path: String,
    pub filesystem: String,
    pub options: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub use_percent: f64,
}
```

### IoStats

```rust
pub struct IoStats {
    pub device: String,
    pub reads_completed: u64,
    pub writes_completed: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub io_in_progress: u64,
    pub io_time_ms: u64,
}
```

---

## System Types

**Module:** `types::system`

### SystemInfo

```rust
pub struct SystemInfo {
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub architecture: String,
    pub uptime_seconds: u64,
    pub boot_time: u64,            // Unix timestamp
}
```

### KernelInfo

```rust
pub struct KernelInfo {
    pub version: String,
    pub release: String,
    pub architecture: String,
    pub command_line: String,
}
```

### CpuInfo

```rust
pub struct CpuInfo {
    pub model_name: String,
    pub cores_physical: u32,
    pub cores_logical: u32,
    pub frequency_mhz: f64,
    pub cache_size_kb: u64,
    pub load_average: [f64; 3],    // [1min, 5min, 15min]
    pub usage_percent: f64,
}
```

---

## Service Types

**Module:** `types::service`

### ServiceInfo

```rust
pub struct ServiceInfo {
    pub name: String,
    pub display_name: String,
    pub state: ServiceState,
    pub enabled: bool,
    pub pid: Option<u32>,
    pub description: Option<String>,
}
```

### ServiceState

```rust
pub enum ServiceState {
    Running,
    Stopped,
    Failed,
    Reloading,
    Activating,
    Deactivating,
    Unknown,
}
```

Also derives `Copy`, `PartialEq`, `Eq`.

### ServiceAction

```rust
pub enum ServiceAction {
    Start,
    Stop,
    Restart,
    Reload,
    Enable,
    Disable,
}
```

Also derives `Copy`, `PartialEq`, `Eq`.

---

## Security Types

**Module:** `types::security`

### UserInfo

```rust
pub struct UserInfo {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
    pub groups: Vec<String>,
}
```

### GroupInfo

```rust
pub struct GroupInfo {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}
```

### KernelModule

```rust
pub struct KernelModule {
    pub name: String,
    pub size_bytes: u64,
    pub used_by: Vec<String>,
    pub state: ModuleState,
}
```

### ModuleState

```rust
pub enum ModuleState {
    Live,
    Loading,
    Unloading,
    Unknown,
}
```

Also derives `Copy`, `PartialEq`, `Eq`.

### SecurityStatus

```rust
pub struct SecurityStatus {
    pub selinux: Option<LsmStatus>,
    pub apparmor: Option<LsmStatus>,
    pub firewall_active: bool,
    pub root_login_allowed: bool,
    pub password_auth_ssh: bool,
}
```

### LsmStatus

```rust
pub struct LsmStatus {
    pub enabled: bool,
    pub mode: String,
}
```

---

## Log Types

**Module:** `types::log`

### LogEntry

```rust
pub struct LogEntry {
    pub timestamp: u64,            // Unix timestamp
    pub level: LogLevel,
    pub unit: Option<String>,
    pub message: String,
    pub pid: Option<u32>,
    pub source: Option<String>,
}
```

### LogLevel

```rust
pub enum LogLevel {
    Emergency,
    Alert,
    Critical,
    Error,
    Warning,
    Notice,
    Info,
    Debug,
}
```

Also derives `Copy`, `PartialEq`, `Eq`, `PartialOrd`, `Ord`. Ordered from most severe (Emergency) to least (Debug).

### LogQuery

```rust
pub struct LogQuery {
    pub unit: Option<String>,
    pub level: Option<LogLevel>,
    pub since: Option<u64>,        // Unix timestamp
    pub until: Option<u64>,        // Unix timestamp
    pub limit: Option<u32>,
    pub grep: Option<String>,
}
```

Derives `Default` (all fields `None`).

---

## Probe Types

**Module:** `types::probe`

*Future -- Phase 5. Types are defined but not yet used by any backend.*

### ProbeHandle

```rust
pub struct ProbeHandle(pub u64);
```

Also derives `Copy`, `PartialEq`, `Eq`, `Hash`.

### ProbeConfig

```rust
pub struct ProbeConfig {
    pub probe_type: ProbeType,
    pub target: Option<String>,
    pub filter: Option<String>,
}
```

### ProbeType

```rust
pub enum ProbeType {
    SyscallTrace,
    NetworkMonitor,
}
```

Also derives `Copy`, `PartialEq`, `Eq`.

### ProbeInfo

```rust
pub struct ProbeInfo {
    pub handle: ProbeHandle,
    pub probe_type: ProbeType,
    pub target: Option<String>,
    pub events_captured: u64,
}
```

### ProbeEvent

```rust
pub struct ProbeEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub process_name: String,
    pub event_type: String,
    pub details: String,
}
```

---

## Tuning Types

**Module:** `types::tuning`

### TunableParam

```rust
pub struct TunableParam {
    pub key: String,
    pub value: TunableValue,
    pub description: Option<String>,
}
```

### TunableValue

```rust
pub enum TunableValue {
    String(String),
    Integer(i64),
    Boolean(bool),
}
```

Also derives `PartialEq`.

---

## Audit Types

**Module:** `audit` (not under `types/`)

### AuditEntry

```rust
pub struct AuditEntry {
    pub timestamp: u64,            // Unix timestamp
    pub agent: String,
    pub profile: String,
    pub tool: String,
    pub resource: Option<String>,
    pub allowed: bool,
    pub dry_run: bool,
    pub reason: Option<String>,
    pub outcome: AuditOutcome,
}
```

### AuditOutcome

```rust
pub enum AuditOutcome {
    Success,
    Denied,
    DryRun,
    Failed,
}
```

Also derives `Copy`, `PartialEq`, `Eq`.

### AuditLog Trait

```rust
pub trait AuditLog: Send + Sync {
    fn log(&self, entry: &AuditEntry);
}
```

---

## Policy Types

See [policy.md](policy.md) for the full policy engine reference, including `Policy`, `EffectivePolicy`, `PolicyDecision`, `PolicyRule`, `Action`, `RuleTarget`, `ResourceFilter`, `ResourceContext`, `Profile`, `Role`, and `Capability`.
