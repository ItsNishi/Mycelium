# Changelog

All notable changes to Mycelium are documented in this file.

## [Unreleased]

## [0.1.0] - 2026-03-02

Initial public release. All six development phases complete.

### Phase 6: eBPF Probes

- eBPF programs for syscall tracing (`raw_tracepoint/sys_enter`) and network monitoring (`tracepoint/sock/inet_sock_set_state`)
- `mycelium-ebpf-common` crate with shared `#[repr(C)]` event types (`#![no_std]`)
- Aya-based probe loader behind `ebpf` feature flag in `mycelium-linux`
- Ring buffer polling threads with mpsc channel pipeline (10K event capacity)
- x86_64 syscall name table (~350 entries)
- 4 MCP tools: `probe_attach`, `probe_detach`, `probe_list`, `probe_read`
- CLI probe subcommands: `attach`, `detach`, `list`, `events` (`--follow`, `--limit`)
- IPv6 support with dual-stack address formatting
- Drop counter tracking (kernel + userspace ring buffer drops)
- 53 integration tests across all crates

### Phase 5: Cross-Platform Feature Parity

- **Linux backend** feature parity with Windows:
  - Process threads via `/proc/[pid]/task/`
  - Process modules from `/proc/[pid]/maps` (shared library grouping)
  - Process privileges via capability bitmask decoding (41 Linux caps)
  - Process handles via `/proc/[pid]/fd/` with type classification
  - Token inspection (UIDs, GIDs, capabilities, seccomp, session ID)
  - Memory search with chunked reading and permission filtering
  - Persistence scanning (cron, systemd timers, init scripts, XDG autostart, shell profiles, udev rules)
  - Hook detection (LD_PRELOAD, suspicious library paths, ptrace attachment)
- **Windows backend** expansion:
  - PE parsing, privilege escalation checks, persistence scanning, hook detection, handle enumeration
  - Expanded core types for cross-platform parity (security, network, process, service, memory)
  - MCP rate limiting and error mapping
- 68 new unit tests (245 total workspace-wide)

### Phase 4: Windows Backend

- `mycelium-windows` crate implementing all Platform trait methods
- Process management via sysinfo
- Memory operations via WinAPI (`VirtualQueryEx`, `ReadProcessMemory`, `WriteProcessMemory`)
- Network: sysinfo for interfaces, netstat parsing, WMI for firewall, netsh for mutations
- Storage: sysinfo for disks/mounts, WMI for partitions and I/O stats
- System info via sysinfo + Windows registry
- Tuning via registry with sysctl-style key mapping
- Services via WMI, `sc.exe`, `wevtutil`
- Security via WMI, `driverquery`, `netsh`
- Entire crate gated behind `#![cfg(target_os = "windows")]`

### Phase 3: Write Operations

- Process kill/signal support
- Firewall rule management
- Service control (start, stop, restart, enable, disable)
- Sysctl tunable writes
- Direct process memory access (maps, read, write)
- `MemoryRegion` type and `memory_access` policy capability
- Policy context forwarding for resource filters (service names, tunable prefixes, PID ranges)
- Grep pattern length validation (256-char limit) to prevent ReDoS

### Phase 2: MCP Server

- `mycelium-mcp` crate exposing tools via JSON-RPC over stdio (MCP protocol 2024-11-05)
- Policy enforcement on every tool call
- Audit logging with per-agent tracking and dry-run mode
- All read operations wired as MCP tools

### Phase 1: Foundation

- `mycelium-core` crate: types, `Platform` trait, custom error enum, policy engine (zero dependencies by default)
- `mycelium-linux` crate: Linux backend reading from `/proc`, `/sys`, `systemctl`, `journalctl`
- `mycelium-cli` crate: CLI binary with table/JSON output via clap
- Role-based policy engine with presets (`admin`, `operator`, `read-only`, `custom`)
- Capability groups, resource filters, specificity-based rule evaluation
- 87 unit tests for Linux backend parsing logic
- Full documentation suite (architecture, platform API, types, CLI, policy, development guide)
