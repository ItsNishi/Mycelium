# Platform API Reference

The `Platform` trait defines the interface that all OS backends implement. Every method returns `Result<T>` where errors are `MyceliumError` variants.

## Platform Trait

```rust
pub trait Platform: Send + Sync {
    // 46 methods: 35 read + 7 write + 4 sensitive
}
```

All methods are synchronous. The MCP server wraps calls with `tokio::task::spawn_blocking` for async contexts. `/proc` reads are kernel-backed memory operations that complete in microseconds.

## Methods by Category

### Process (11 methods)

| Method | Signature | Read/Write |
|--------|-----------|------------|
| `list_processes` | `(&self) -> Result<Vec<ProcessInfo>>` | Read |
| `inspect_process` | `(&self, pid: u32) -> Result<ProcessInfo>` | Read |
| `process_resources` | `(&self, pid: u32) -> Result<ProcessResource>` | Read |
| `kill_process` | `(&self, pid: u32, signal: Signal) -> Result<()>` | **Write** |
| `list_process_threads` | `(&self, pid: u32) -> Result<Vec<ThreadInfo>>` | Read |
| `list_process_modules` | `(&self, pid: u32) -> Result<Vec<ProcessModule>>` | Read |
| `process_environment` | `(&self, pid: u32) -> Result<Vec<(String, String)>>` | Read |
| `list_process_privileges` | `(&self, pid: u32) -> Result<Vec<PrivilegeInfo>>` | Read |
| `list_process_handles` | `(&self, pid: u32) -> Result<Vec<HandleInfo>>` | Read |
| `inspect_pe` | `(&self, target: &PeTarget) -> Result<PeInfo>` | Read |
| `inspect_process_token` | `(&self, pid: u32) -> Result<TokenInfo>` | Read |

Methods from `list_process_threads` onwards have default implementations that return `Err(MyceliumError::Unsupported(...))`, so backends that don't implement them compile without changes.

### Memory (7 methods)

| Method | Signature | Read/Write |
|--------|-----------|------------|
| `memory_info` | `(&self) -> Result<MemoryInfo>` | Read |
| `process_memory` | `(&self, pid: u32) -> Result<ProcessMemory>` | Read |
| `process_memory_maps` | `(&self, pid: u32) -> Result<Vec<MemoryRegion>>` | **Sensitive** |
| `read_process_memory` | `(&self, pid: u32, address: u64, size: usize) -> Result<Vec<u8>>` | **Sensitive** |
| `write_process_memory` | `(&self, pid: u32, address: u64, data: &[u8]) -> Result<usize>` | **Write** |
| `search_process_memory` | `(&self, pid: u32, pattern: &SearchPattern, options: &MemorySearchOptions) -> Result<Vec<MemoryMatch>>` | **Sensitive** |
| `protect_process_memory` | `(&self, pid: u32, address: u64, size: usize, protection: &str) -> Result<String>` | **Write** |

`search_process_memory` and `protect_process_memory` have default implementations that return `Err(MyceliumError::Unsupported(...))`.

### Network (7 methods)

| Method | Signature | Read/Write |
|--------|-----------|------------|
| `list_interfaces` | `(&self) -> Result<Vec<NetworkInterface>>` | Read |
| `list_connections` | `(&self) -> Result<Vec<Connection>>` | Read |
| `list_routes` | `(&self) -> Result<Vec<Route>>` | Read |
| `list_open_ports` | `(&self) -> Result<Vec<OpenPort>>` | Read |
| `list_firewall_rules` | `(&self) -> Result<Vec<FirewallRule>>` | Read |
| `add_firewall_rule` | `(&self, rule: &FirewallRule) -> Result<()>` | **Write** |
| `remove_firewall_rule` | `(&self, rule_id: &str) -> Result<()>` | **Write** |

### Storage (4 methods)

| Method | Signature | Read/Write |
|--------|-----------|------------|
| `list_disks` | `(&self) -> Result<Vec<DiskInfo>>` | Read |
| `list_partitions` | `(&self) -> Result<Vec<Partition>>` | Read |
| `list_mounts` | `(&self) -> Result<Vec<MountPoint>>` | Read |
| `io_stats` | `(&self) -> Result<Vec<IoStats>>` | Read |

### System (4 methods)

| Method | Signature | Read/Write |
|--------|-----------|------------|
| `system_info` | `(&self) -> Result<SystemInfo>` | Read |
| `kernel_info` | `(&self) -> Result<KernelInfo>` | Read |
| `cpu_info` | `(&self) -> Result<CpuInfo>` | Read |
| `uptime` | `(&self) -> Result<u64>` | Read |

### Tuning (3 methods)

| Method | Signature | Read/Write |
|--------|-----------|------------|
| `get_tunable` | `(&self, key: &str) -> Result<TunableValue>` | Read |
| `list_tunables` | `(&self, prefix: &str) -> Result<Vec<TunableParam>>` | Read |
| `set_tunable` | `(&self, key: &str, value: &TunableValue) -> Result<TunableValue>` | **Write** |

`set_tunable` returns the previous value on success.

### Services (3 methods)

| Method | Signature | Read/Write |
|--------|-----------|------------|
| `list_services` | `(&self) -> Result<Vec<ServiceInfo>>` | Read |
| `service_status` | `(&self, name: &str) -> Result<ServiceInfo>` | Read |
| `service_action` | `(&self, name: &str, action: ServiceAction) -> Result<()>` | **Write** |

### Logs (1 method)

| Method | Signature | Read/Write |
|--------|-----------|------------|
| `read_logs` | `(&self, query: &LogQuery) -> Result<Vec<LogEntry>>` | Read |

### Security (6 methods)

| Method | Signature | Read/Write |
|--------|-----------|------------|
| `list_users` | `(&self) -> Result<Vec<UserInfo>>` | Read |
| `list_groups` | `(&self) -> Result<Vec<GroupInfo>>` | Read |
| `list_kernel_modules` | `(&self) -> Result<Vec<KernelModule>>` | Read |
| `security_status` | `(&self) -> Result<SecurityStatus>` | Read |
| `list_persistence_entries` | `(&self) -> Result<Vec<PersistenceEntry>>` | Read |
| `detect_hooks` | `(&self, pid: u32) -> Result<Vec<HookInfo>>` | **Sensitive** |

`list_persistence_entries` and `detect_hooks` have default implementations that return `Err(MyceliumError::Unsupported(...))`.

## ProbePlatform Trait

Extended trait for eBPF probe support. Separate from `Platform` so backends that don't support probes (e.g., Windows) don't need to stub these methods.

```rust
pub trait ProbePlatform: Platform {
    fn attach_probe(&self, config: &ProbeConfig) -> Result<ProbeHandle>;
    fn detach_probe(&self, handle: ProbeHandle) -> Result<()>;
    fn list_probes(&self) -> Result<Vec<ProbeInfo>>;
    fn read_probe_events(&self, handle: &ProbeHandle) -> Result<Vec<ProbeEvent>>;
}
```

| Method | Signature | Read/Write |
|--------|-----------|------------|
| `attach_probe` | `(&self, config: &ProbeConfig) -> Result<ProbeHandle>` | **Write** |
| `detach_probe` | `(&self, handle: ProbeHandle) -> Result<()>` | **Write** |
| `list_probes` | `(&self) -> Result<Vec<ProbeInfo>>` | Read |
| `read_probe_events` | `(&self, handle: &ProbeHandle) -> Result<Vec<ProbeEvent>>` | Read |

**Status:** Implemented in Phase 6 (Linux only, behind `ebpf` feature flag). Requires `bpf-linker`, nightly Rust for eBPF compilation, and root/CAP_BPF at runtime. Uses the aya framework for pure-Rust eBPF loading.

## Error Handling

All methods return `Result<T>`, an alias for `core::result::Result<T, MyceliumError>`.

### MyceliumError Variants

| Variant | Fields | When Returned |
|---------|--------|---------------|
| `PermissionDenied` | `String` | Caller lacks OS privileges (e.g., reading `/proc/[pid]/io` for another user's process) |
| `NotFound` | `String` | Resource doesn't exist (e.g., PID not found, service not found) |
| `OsError` | `{ code: i32, message: String }` | OS-level error with raw errno |
| `ParseError` | `String` | Failed to parse `/proc` output or command output into structured type |
| `Unsupported` | `String` | Operation not supported on this platform (e.g., write ops in Phase 1) |
| `IoError` | `std::io::Error` | Wrapper around std I/O errors. Implements `From<std::io::Error>` |
| `DryRun` | `String` | Write operation skipped because dry-run mode is active |
| `Timeout` | `String` | Operation timed out |
| `ProbeError` | `String` | eBPF probe error (attach failure, permission, etc.) |
| `ConfigError` | `String` | Invalid policy config, bad TOML, etc. |
| `PolicyDenied` | `{ tool: String, reason: String }` | Policy engine denied the operation |

### Display Format

```
permission denied: cannot read /proc/1234/io
not found: no process with PID 99999
OS error 13: Permission denied
parse error: invalid state in /proc/1234/stat
unsupported: write operations not implemented in Phase 1
I/O error: No such file or directory (os error 2)
dry-run: would kill process 1234 with SIGTERM
policy denied tool 'process_kill': read-only: no process management
```

### Error Source Chain

`IoError` implements `std::error::Error::source()`, returning the wrapped `std::io::Error`. All other variants return `None`.

## Type References

All parameter and return types are documented in [types.md](types.md).
