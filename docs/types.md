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

### ThreadInfo

```rust
pub struct ThreadInfo {
    pub tid: u32,
    pub pid: u32,
    pub priority: i32,
}
```

### ProcessModule

```rust
pub struct ProcessModule {
    pub name: String,              // e.g. "ntdll.dll"
    pub path: String,              // full path
    pub base_address: u64,
    pub size: u64,
}
```

### PrivilegeInfo

```rust
pub struct PrivilegeInfo {
    pub name: String,              // e.g. "SeDebugPrivilege"
    pub enabled: bool,             // true if currently enabled in the token
}
```

### HandleInfo

```rust
pub struct HandleInfo {
    pub handle_value: u64,
    pub object_type: String,       // e.g. "File", "Key", "Mutant", "Section"
    pub name: Option<String>,      // e.g. "\Device\HarddiskVolume3\Windows\System32\ntdll.dll"
    pub access_mask: u32,
}
```

### PeTarget

```rust
pub enum PeTarget {
    Pid(u32),                      // Read PE from process memory
    Path(String),                  // Read PE from file on disk
}
```

### PeInfo

```rust
pub struct PeInfo {
    pub machine: String,           // e.g. "AMD64", "I386"
    pub characteristics: Vec<String>, // e.g. ["EXECUTABLE_IMAGE", "LARGE_ADDRESS_AWARE"]
    pub entry_point: u64,
    pub image_base: u64,
    pub image_size: u32,
    pub timestamp: u64,
    pub subsystem: String,         // e.g. "WINDOWS_CUI", "WINDOWS_GUI"
    pub sections: Vec<PeSection>,
    pub imports: Vec<PeImport>,
    pub exports: Vec<PeExport>,
}
```

### PeSection

```rust
pub struct PeSection {
    pub name: String,              // e.g. ".text", ".rdata", ".data"
    pub virtual_address: u64,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub characteristics: Vec<String>, // e.g. ["CNT_CODE", "MEM_EXECUTE", "MEM_READ"]
}
```

### PeImport

```rust
pub struct PeImport {
    pub dll_name: String,          // e.g. "KERNEL32.dll"
    pub functions: Vec<String>,    // e.g. ["CreateFileW", "ReadFile"]
}
```

### PeExport

```rust
pub struct PeExport {
    pub ordinal: u16,
    pub name: Option<String>,
    pub rva: u32,
}
```

### TokenInfo

```rust
pub struct TokenInfo {
    pub pid: u32,
    pub user: String,              // e.g. "DESKTOP-ABC\User"
    pub integrity_level: String,   // e.g. "High", "Medium", "System"
    pub token_type: String,        // e.g. "Primary", "Impersonation"
    pub impersonation_level: Option<String>, // e.g. "Delegation", "Impersonation"
    pub elevation_type: String,    // e.g. "Full", "Limited", "Default"
    pub is_elevated: bool,
    pub is_restricted: bool,
    pub session_id: u32,
    pub groups: Vec<TokenGroup>,
    pub privileges: Vec<PrivilegeInfo>,
}
```

### TokenGroup

```rust
pub struct TokenGroup {
    pub name: String,              // e.g. "BUILTIN\Administrators"
    pub sid: String,               // e.g. "S-1-5-32-544"
    pub attributes: Vec<String>,   // e.g. ["SE_GROUP_ENABLED", "SE_GROUP_OWNER"]
}
```

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

### MemoryRegion

A single region from a process's virtual memory map (`/proc/<pid>/maps`).

```rust
pub struct MemoryRegion {
    pub start_address: u64,
    pub end_address: u64,
    pub permissions: String,      // "rwxp", "r-xp", etc.
    pub offset: u64,
    pub device: String,           // "08:01"
    pub inode: u64,
    pub pathname: Option<String>, // "/lib/libc.so", "[heap]", "[stack]"
}
```

### SearchPattern

What to search for in process memory.

```rust
pub enum SearchPattern {
    Bytes(Vec<u8>),               // Raw bytes (hex-encoded in MCP/CLI)
    Utf8(String),                 // UTF-8 string
    Utf16(String),                // UTF-16LE string
}
```

### MemoryMatch

A single match found during memory search.

```rust
pub struct MemoryMatch {
    pub address: u64,              // Absolute address of the match
    pub region_start: u64,         // Start of the containing memory region
    pub region_permissions: String, // e.g. "rw--"
    pub region_pathname: Option<String>,
    pub context_bytes: Vec<u8>,    // Bytes around the match for context
}
```

### MemorySearchOptions

Options controlling memory search behavior.

```rust
pub struct MemorySearchOptions {
    pub max_matches: usize,        // Max matches before stopping (default 100)
    pub context_size: usize,       // Context bytes around each match (default 32)
    pub permissions_filter: String, // e.g. "rw" for readable+writable only
}
```

Derives `Default` (`max_matches: 100`, `context_size: 32`, `permissions_filter: ""`).

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

### PersistenceEntry

A Windows persistence mechanism entry (registry run key, scheduled task, service, etc.).

```rust
pub struct PersistenceEntry {
    pub persistence_type: PersistenceType,
    pub name: String,
    pub location: String,          // e.g. registry path, task folder
    pub value: String,             // e.g. command line, executable path
    pub enabled: bool,
    pub description: Option<String>,
}
```

### PersistenceType

```rust
pub enum PersistenceType {
    RegistryRun,
    ScheduledTask,
    Service,
    StartupFolder,
    WmiSubscription,
    ComHijack,
}
```

Also derives `Copy`, `PartialEq`, `Eq`.

### HookInfo

A detected API hook (inline, IAT, or EAT) in a process.

```rust
pub struct HookInfo {
    pub hook_type: HookType,
    pub module: String,            // e.g. "ntdll.dll"
    pub function: String,          // e.g. "NtCreateFile"
    pub address: u64,              // Address of the hooked function
    pub expected_bytes: Vec<u8>,   // Original bytes from disk
    pub actual_bytes: Vec<u8>,     // Current bytes in memory
    pub destination: Option<u64>,  // Where the hook redirects to
    pub destination_module: Option<String>, // Module containing the destination
}
```

### HookType

```rust
pub enum HookType {
    InlineHook,                    // Modified function prologue (JMP, MOV+JMP, PUSH+RET)
    IatHook,                       // Modified Import Address Table entry
    EatHook,                       // Modified Export Address Table entry
}
```

Also derives `Copy`, `PartialEq`, `Eq`.

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
