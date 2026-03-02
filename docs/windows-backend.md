# Windows Backend Reference

The `mycelium-windows` crate implements the `Platform` trait for Windows using sysinfo, WinAPI, and WMI.

## WindowsPlatform

```rust
pub struct WindowsPlatform;
```

Stateless, zero-sized struct — identical pattern to `LinuxPlatform`. Every call queries fresh data from the OS. No caching, no stale state.

## Privilege Management

### SeDebugPrivilege

Many Windows process-inspection APIs require `SeDebugPrivilege` on the caller's token. This privilege is only available to elevated (admin) processes.

| Function | Purpose |
|----------|---------|
| `is_elevated()` | Checks if the current process is running with admin elevation |
| `enable_debug_privilege()` | Enables `SeDebugPrivilege` on the current process token |
| `ensure_debug_privilege()` | Cached one-shot wrapper — calls `enable_debug_privilege()` once, returns the cached result on subsequent calls |

`ensure_debug_privilege()` uses `OnceLock` so the privilege is requested at most once per process lifetime. Functions that need it call `let _ = ensure_debug_privilege();` — the result is intentionally ignored so non-admin callers get a best-effort attempt rather than a hard failure.

## Data Sources by Method Category

| Category | Data Source | Notes |
|----------|-------------|-------|
| Process — list/inspect/resources (3) | `sysinfo` crate | Cross-platform; user populated via token `LookupAccountSidW` |
| Process — kill (1) | `TerminateProcess` | Only supports Term/Kill/Int on Windows |
| Process — threads (1) | `CreateToolhelp32Snapshot` + `Thread32First`/`Thread32Next` | No privilege needed |
| Process — modules (1) | `EnumProcessModules` + `GetModuleFileNameExW` + `GetModuleInformation` | Requires `SeDebugPrivilege` for other processes |
| Process — environment (1) | `NtQueryInformationProcess` + `ReadProcessMemory` PEB traversal | Reads UTF-16LE env block; max 256 KiB |
| Process — privileges (1) | `GetTokenInformation(TokenPrivileges)` + `LookupPrivilegeNameW` | Requires `PROCESS_QUERY_INFORMATION` on target |
| Process — handles (1) | `NtQuerySystemInformation(SystemHandleInformation)` + `NtQueryObject` | Enumerates all system handles, filters by PID; skips types that may hang (ALPC ports) |
| Process — PE inspect (1) | Manual PE header parsing (`ReadProcessMemory` or `std::fs::read`) | Parses DOS/PE headers, sections, imports (ILT walk), exports; supports both PID and file path |
| Process — token (1) | `OpenProcessToken` + `GetTokenInformation` (multiple info classes) | Integrity via `TokenIntegrityLevel`, groups via `TokenGroups`, elevation via `TokenElevationType` |
| Memory — system (2) | `sysinfo` crate | `buffers_bytes` and `cached_bytes` always 0 (Linux-specific) |
| Memory — maps (1) | `VirtualQueryEx` + `GetMappedFileNameW` | Requires `PROCESS_QUERY_INFORMATION \| PROCESS_VM_READ` |
| Memory — read (1) | `ReadProcessMemory` | Requires `PROCESS_VM_READ`; max 1 MiB |
| Memory — write (1) | `WriteProcessMemory` | Requires `PROCESS_VM_WRITE \| PROCESS_VM_OPERATION`; max 1 MiB |
| Memory — search (1) | `VirtualQueryEx` + `ReadProcessMemory` (chunked scan) | Scans committed regions in 1 MiB chunks with overlap; supports byte/UTF-8/UTF-16 patterns; permission filtering |
| Memory — protect (1) | `VirtualProtectEx` | Requires `PROCESS_VM_OPERATION`; max 16 MiB |
| Network (7) | `GetExtendedTcpTable`/`GetExtendedUdpTable`, `GetIpForwardTable2`, WMI | Connections via IP Helper APIs; routes via `GetIpForwardTable2` (IPv4+IPv6); firewall via WMI; interface speed from `Win32_NetworkAdapter.Speed` |
| Storage (4) | `sysinfo` + WMI | Disk I/O stats via WMI; partition filesystem/label/UUID from `Win32_LogicalDisk` |
| System (4) | `sysinfo` + registry | Kernel info from registry |
| Tuning (3) | Windows Registry | 11 prefix mappings to `HKLM\SYSTEM\CurrentControlSet` keys; raw `registry.` prefix for arbitrary paths |
| Services (3) | Service Control Manager | Listing/status via `Win32_Service` WMI; actions via direct SCM APIs (`StartServiceW`, `ControlService`, `ChangeServiceConfigW`); dependencies via `Win32_DependentService` |
| Logs (1) | Windows Event Log | Via `wevtutil` command; supports `since`/`until` time-range filtering |
| Security — users/groups (2) | NetAPI32 | User enumeration via `NetUserEnum` (level 3); groups via `NetLocalGroupEnum`/`NetLocalGroupGetMembers` |
| Security — kernel modules (1) | WMI `Win32_SystemDriver` | File sizes obtained from `std::fs::metadata`; driver paths expanded |
| Security — status (1) | Registry + SSH config | Firewall active check, root login, password auth |
| Security — persistence (1) | Registry + WMI + `schtasks` + filesystem | Scans Run/RunOnce keys, scheduled tasks (CSV parsing), services, startup folder, WMI event subscriptions, COM hijacks |
| Security — hooks (1) | `ReadProcessMemory` + on-disk PE comparison | Detects inline hooks (JMP/MOV+JMP/PUSH+RET patterns), IAT hooks, EAT hooks; compares memory against disk image accounting for relocations |

## Memory Protection String Mapping

The `protect_process_memory` function accepts and returns Unix-style permission strings:

| String | Windows Flag | Description |
|--------|-------------|-------------|
| `"---"` | `PAGE_NOACCESS` | No access |
| `"r--"` | `PAGE_READONLY` | Read only |
| `"rw-"` | `PAGE_READWRITE` | Read + write |
| `"--x"` | `PAGE_EXECUTE` | Execute only |
| `"r-x"` | `PAGE_EXECUTE_READ` | Read + execute |
| `"rwx"` | `PAGE_EXECUTE_READWRITE` | Read + write + execute |

When reading existing protection (e.g., from `process_memory_maps`), `PAGE_WRITECOPY` maps to `"rw-"` and `PAGE_EXECUTE_WRITECOPY` maps to `"rwx"`. A `PAGE_GUARD` flag appends `g` as the fourth character (e.g., `"rw-g"`).

## Size Limits

| Operation | Maximum | Constant |
|-----------|---------|----------|
| `read_process_memory` | 1 MiB (1,048,576 bytes) | `MAX_READ_SIZE` |
| `write_process_memory` | 1 MiB (1,048,576 bytes) | `MAX_WRITE_SIZE` |
| `protect_process_memory` | 16 MiB (16,777,216 bytes) | `MAX_PROTECT_SIZE` |
| `search_process_memory` chunk | 1 MiB (1,048,576 bytes) | `SEARCH_CHUNK_SIZE` |

## Safety Limits

| Operation | Maximum | Constant |
|-----------|---------|----------|
| `list_process_threads` | 10,000 threads | `MAX_THREADS` |
| `list_process_modules` | 4,096 modules | `MAX_MODULES` |
| `search_process_memory` matches | 10,000 matches | `MAX_SEARCH_MATCHES` |
| `search_process_memory` context | 256 bytes | `MAX_CONTEXT_SIZE` |
| `search_process_memory` region skip | 256 MiB | `MAX_SEARCH_REGION_SIZE` |

## Permission Matrix

| Operation | Non-admin | Admin (elevated) |
|-----------|-----------|-------------------|
| `list_processes` | All processes visible | All processes visible |
| `inspect_process` | All processes | All processes |
| `process_resources` | All processes | All processes |
| `kill_process` | Own processes only | Any process |
| `memory_info` | Works | Works |
| `process_memory` | All processes | All processes |
| `process_memory_maps` | Own processes only | Any process |
| `read_process_memory` | Own processes only | Any process |
| `write_process_memory` | Own processes only | Any process |
| `search_process_memory` | Own processes only | Any process |
| `protect_process_memory` | Own processes only | Any process |
| `list_process_threads` | All processes | All processes |
| `list_process_modules` | Own processes only | Any process |
| `process_environment` | Own processes only | Any process |
| `list_process_privileges` | Own processes only | Any process |
| `list_process_handles` | Requires admin | Any process |
| `inspect_pe` | Own processes / any file | Any process / any file |
| `inspect_process_token` | Own processes only | Any process |
| `list_persistence_entries` | Most locations | All locations |
| `detect_hooks` | Own processes only | Any process |
| Network operations | Read: all; Write: requires admin | Full access |
| Service operations | Read: all; Write: requires admin | Full access |
| Tuning operations | Read: most keys; Write: requires admin | Full access |

## Edge Cases and Known Limitations

- **`buffers_bytes` and `cached_bytes`** in `MemoryInfo` are always 0 — these are Linux-specific concepts with no direct Windows equivalent.
- **`shared_bytes`, `text_bytes`, `data_bytes`** in `ProcessMemory` — populated via `VirtualQueryEx` region walk: shared = `MEM_MAPPED | MEM_IMAGE`, text = execute-flagged regions, data = `MEM_PRIVATE` + `PAGE_READWRITE`. Falls back to 0 if handle cannot be opened.
- **`open_fds`** in `ProcessResource` — populated via `GetProcessHandleCount`. Returns 0 for processes that cannot be opened (system processes, access denied).
- **`user`** in `ProcessInfo` — populated via token inspection (`OpenProcessToken` → `GetTokenInformation` → `LookupAccountSidW`). Returns `"DOMAIN\User"` format. Empty for system processes that cannot be opened.
- **`uid`** in `ProcessInfo` is always 0 — Windows uses SIDs, not numeric UIDs. User `uid`/`gid` in `UserInfo` are populated with RIDs from `NetUserEnum` level 3.
- **Signals** — only `Term`, `Kill`, and `Int` are supported. All three result in process termination. Unix-specific signals (`Hup`, `Usr1`, `Usr2`, `Stop`, `Cont`) return `Unsupported`.
- **System processes** (PID 0, PID 4) — module/memory enumeration will fail with `PermissionDenied` even when elevated, as these are kernel-level pseudo-processes.
- **32-bit vs 64-bit** — a 64-bit Mycelium process cannot enumerate modules of a 32-bit WoW64 process using `EnumProcessModules`. Use `EnumProcessModulesEx` with `LIST_MODULES_ALL` if this becomes a requirement.
- **Thread priority** — `tpBasePri` from `THREADENTRY32` is the base priority (0–31), not the relative priority level.
- **CPU frequency** — `cpu_info()` prefers WMI `CurrentClockSpeed` (real-time MHz) over sysinfo's static cached value.
- **Kernel modules** — listed via WMI `Win32_SystemDriver` instead of `driverquery`. File sizes obtained from `std::fs::metadata`; driver paths with `\SystemRoot\` or `\??\` prefixes are expanded.
- **Partition info** — filesystem, label, and UUID populated from `Win32_LogicalDisk` via `Win32_LogicalDiskToPartition` association. Partitions without a logical disk mapping will have empty fields.
- **Firewall rules** — port and address filters populated from `MSFT_NetFirewallPortFilter` and `MSFT_NetFirewallAddressFilter` in the `StandardCimv2` WMI namespace.
- **Network interface speed** — from `Win32_NetworkAdapter.Speed` (bps converted to Mbps). Virtual/loopback adapters may report 0 or None.
- **Service dependencies** — from `Win32_DependentService` WMI association. Only direct dependencies are listed.
- **Process environment** — read via PEB traversal (`NtQueryInformationProcess` → PEB → ProcessParameters → Environment). Limited to 256 KiB. Internal Windows vars (starting with `=`) are skipped. Fails for system processes (PID 0, 4).
- **Log time filtering** — `since`/`until` are compared against parsed `TimeCreated` timestamps. Entries with unparseable timestamps (timestamp = 0) are never filtered out.
- **Handle enumeration** — uses `NtQuerySystemInformation(SystemHandleInformation)` which returns all system handles; filtered by PID. Object names resolved via `NtQueryObject`. Some handle types (ALPC ports, certain events) are skipped to avoid hangs during name resolution.
- **PE parsing** — manual header parsing (no external PE library). Supports PE32 and PE32+ (64-bit). Import resolution walks the Import Lookup Table (ILT). For PID targets, reads via `ReadProcessMemory`; for file targets, reads from disk.
- **Token inspection** — integrity level resolved from `TokenIntegrityLevel` SID (maps well-known RIDs to "Untrusted", "Low", "Medium", "High", "System"). Groups enumerated via `TokenGroups` with `LookupAccountSidW`.
- **Persistence scanning** — scheduled tasks parsed from `schtasks /query /fo CSV /v` output. WMI event subscriptions queried from `__EventFilter`, `__EventConsumer`, `__FilterToConsumerBinding`. COM hijacks scanned from `HKCU\Software\Classes\CLSID`.
- **Hook detection** — compares in-memory code against on-disk PE images. Accounts for relocations (processes relocation fixup records to avoid false positives). Inline hook patterns detected: `JMP rel32`, `JMP [RIP+disp32]`, `MOV RAX, imm64; JMP RAX`, `PUSH imm32; RET`. IAT hooks detected by comparing IAT entries against expected module ranges.
- **Memory search** — reads process memory in 1 MiB chunks with `pattern.len() - 1` byte overlap between chunks to detect cross-boundary matches. Skips `PAGE_NOACCESS` and `PAGE_GUARD` regions. Regions larger than 256 MiB are skipped to prevent excessive reads.
