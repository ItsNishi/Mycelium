# Linux Backend

The `mycelium-linux` crate implements the `Platform` trait for Linux. It reads structured data from `/proc`, `/sys`, and OS commands.

## LinuxPlatform

```rust
pub struct LinuxPlatform;

impl LinuxPlatform {
    pub fn new() -> Self { Self }
}

impl Default for LinuxPlatform {
    fn default() -> Self { Self::new() }
}
```

`LinuxPlatform` is a zero-sized, stateless struct. Every call reads fresh data from the kernel -- no caching, no stale state. This makes it `Send + Sync` without any locking.

## Dependencies

| Crate | Version | Features | Purpose |
|-------|---------|----------|---------|
| `mycelium-core` | workspace | default | Types and trait definition |
| `nix` | 0.29 | `fs`, `hostname`, `net`, `signal`, `user` | POSIX syscalls (uname, getifaddrs, statvfs, kill, getuid) |

## Data Source Reference

### Process

| Method | Source | Details |
|--------|--------|---------|
| `list_processes` | `/proc/[pid]/stat`, `/proc/[pid]/status`, `/proc/[pid]/cmdline` | Iterates `/proc/` for numeric directories |
| `inspect_process` | `/proc/[pid]/stat`, `/proc/[pid]/status`, `/proc/[pid]/cmdline` | Single PID lookup |
| `process_resources` | `/proc/[pid]/stat`, `/proc/[pid]/status`, `/proc/[pid]/fd`, `/proc/[pid]/io`, `/proc/meminfo` | FD count via directory listing, I/O bytes, memory percent |
| `kill_process` | `nix::sys::signal::kill` | Sends signal to process via `kill(2)` |

**Parsing notes:**
- `/proc/[pid]/stat` -- the `comm` field (field 1) is in parentheses and may contain spaces. Parsing finds the last `)` to locate field boundaries correctly.
- State codes: `R`=Running, `S`=Sleeping, `D`=DiskSleep, `T`=Stopped, `Z`=Zombie, `X`=Dead
- `starttime` (field 21) is in clock ticks since boot. Converted to Unix timestamp using `btime` from `/proc/stat` and `CLK_TCK` from `sysconf`.
- `rss` (field 23) is in pages. Multiplied by page size from `sysconf(PAGE_SIZE)`.
- `/proc/[pid]/cmdline` uses null bytes as separators, replaced with spaces.
- Username resolved from UID via `nix::unistd::User::from_uid`.

### Memory

| Method | Source | Details |
|--------|--------|---------|
| `memory_info` | `/proc/meminfo` | MemTotal, MemFree, MemAvailable, Buffers, Cached, SwapTotal, SwapFree |
| `process_memory` | `/proc/[pid]/status` | VmRSS, VmSize, RssFile, RssShmem, VmExe, VmData |
| `process_memory_maps` | `/proc/[pid]/maps` | Parses virtual memory regions (address range, perms, offset, device, inode, pathname) |
| `read_process_memory` | `/proc/[pid]/mem` | Seek + read, 1 MiB max per call, requires ptrace or root |
| `write_process_memory` | `/proc/[pid]/mem` | Seek + write, requires ptrace or root |

**Parsing notes:**
- All `/proc/meminfo` and `/proc/[pid]/status` memory values are in kB, multiplied by 1024 to get bytes.
- `used_bytes = total_bytes - available_bytes` (not `total - free`, since free excludes buffers/cache).
- `shared_bytes` is `RssFile + RssShmem` from `/proc/[pid]/status`.
- `/proc/[pid]/maps` lines: `start-end perms offset dev inode pathname`. Addresses parsed as hex.
- `/proc/[pid]/mem` access: EFAULT (14) and EIO (5) mapped to descriptive "unmapped or inaccessible" errors.

### Network

| Method | Source | Details |
|--------|--------|---------|
| `list_interfaces` | `/sys/class/net/`, `nix::ifaddrs::getifaddrs`, `/proc/net/if_inet6` | Interface names, state, MAC, MTU, traffic stats, addresses |
| `list_connections` | `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6` | Active connections with inode-to-PID mapping |
| `list_routes` | `/proc/net/route` | IPv4 routing table |
| `list_open_ports` | `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6` | Filters for listening state (TCP) and bound sockets (UDP) |
| `list_firewall_rules` | `nft list ruleset -a` or `iptables-save` | Tries nftables first, falls back to iptables |
| `add_firewall_rule` | `nft add rule` or `iptables -A` | Adds firewall rule via nftables or iptables |
| `remove_firewall_rule` | `nft delete rule` or `iptables -D` | Removes firewall rule by handle/ID |

**Interface details:**
- `/sys/class/net/[iface]/address` -- MAC address
- `/sys/class/net/[iface]/mtu` -- MTU
- `/sys/class/net/[iface]/operstate` -- State (up/down/unknown)
- `/sys/class/net/[iface]/statistics/{rx,tx}_{bytes,packets,errors}` -- Traffic stats
- `nix::ifaddrs::getifaddrs` -- IPv4 addresses
- `/proc/net/if_inet6` -- IPv6 addresses (hex format with prefix length)

**Connection parsing:**
- Addresses in `/proc/net/tcp` are little-endian hex. For example, `0100007F:0050` is `127.0.0.1:80`.
- TCP state is a hex byte: `01`=Established, `0A`=Listen, etc.
- PID mapping: iterates `/proc/[pid]/fd/` symlinks, matches `socket:[inode]` against the connection's inode.

**Firewall parsing:**
- nftables: parses `nft list ruleset -a` output. Extracts chain names, rule handles, action keywords (accept/drop/reject/log), dport, and comments.
- iptables: parses `iptables-save` output. Extracts `-A` chain, `-p` protocol, `-s` source, `-d` destination, `--dport` port, `-j` action, `--comment` text.

### Storage

| Method | Source | Details |
|--------|--------|---------|
| `list_disks` | `/sys/block/` | Skips `loop*` and `ram*` devices |
| `list_partitions` | `/proc/partitions` | Skips 2 header lines, filters partitions |
| `list_mounts` | `/proc/mounts`, `nix::sys::statvfs` | Filters pseudo-filesystems |
| `io_stats` | `/proc/diskstats` | Sector-based I/O counters |

**Disk details:**
- `/sys/block/[dev]/device/model` -- Model name
- `/sys/block/[dev]/device/serial` -- Serial number
- `/sys/block/[dev]/size` -- Size in 512-byte sectors
- `/sys/block/[dev]/removable` -- `0` or `1`
- `/sys/block/[dev]/queue/rotational` -- `0` (SSD) or `1` (HDD)

**Mount filtering:**
Pseudo-filesystems are excluded: proc, sysfs, devtmpfs, securityfs, cgroup, cgroup2, pstore, efivarfs, bpf, tracefs, debugfs, configfs, fusectl, hugetlbfs, mqueue, autofs, rpc_pipefs, devpts.

**I/O stats fields from `/proc/diskstats`:**
- Field 3: reads completed
- Field 5: sectors read (multiply by 512 for bytes)
- Field 7: writes completed
- Field 9: sectors written (multiply by 512 for bytes)
- Field 11: I/O operations in progress
- Field 12: time spent doing I/O (ms)

### System

| Method | Source | Details |
|--------|--------|---------|
| `system_info` | `nix::uname`, `/etc/os-release` or `/usr/lib/os-release`, `/proc/uptime`, `/proc/stat` | Hostname, OS, architecture, uptime, boot time |
| `kernel_info` | `nix::uname`, `/proc/cmdline` | Kernel release, version, architecture, command line |
| `cpu_info` | `/proc/cpuinfo`, `/proc/loadavg`, `/proc/stat` | Model, cores, frequency, cache, load, usage |
| `uptime` | `/proc/uptime` | First field (float, truncated to u64) |

**CPU details:**
- Physical cores counted by unique `physical id` values in `/proc/cpuinfo`.
- Logical cores counted by `processor` entries.
- CPU usage is a snapshot: `(user + nice + system) / total * 100` from the `cpu` line of `/proc/stat`.
- Load average: first 3 space-separated floats from `/proc/loadavg`.

### Tuning

| Method | Source | Details |
|--------|--------|---------|
| `get_tunable` | `/proc/sys/` | Key dots mapped to path separators |
| `list_tunables` | `/proc/sys/` | Recursive directory traversal |
| `set_tunable` | `/proc/sys/` | Writes value to sysctl path, returns previous value |

**Key mapping:** `net.ipv4.ip_forward` becomes `/proc/sys/net/ipv4/ip_forward`. Values are parsed as integers first, falling back to strings. Permission-denied errors on individual files are handled gracefully during listing.

### Services

| Method | Source | Details |
|--------|--------|---------|
| `list_services` | `systemctl list-units --type=service --all --no-pager --no-legend --plain` | Parses whitespace-delimited output |
| `service_status` | `systemctl show <name>.service --no-pager` | Parses key=value lines |
| `service_action` | `systemctl <action> <name>.service` | Start, stop, restart, reload, enable, disable |

**State mapping from systemctl:**
- `running` -> Running
- `exited`, `dead` -> Stopped
- `failed` -> Failed
- `activating` -> Activating
- `deactivating` -> Deactivating
- `reloading` -> Reloading

**systemctl show fields:**
- `Description` -> display_name
- `ActiveState` -> state
- `UnitFileState` -> enabled (== "enabled")
- `MainPID` -> pid (only if > 0)

### Logs

| Method | Source | Details |
|--------|--------|---------|
| `read_logs` | `journalctl` | Multiple flags based on LogQuery fields |

**journalctl flags:**
- `--no-pager --output=short-unix` -- always present
- `-u UNIT` -- if `query.unit` is set
- `-p PRIORITY` -- if `query.level` is set (0=Emergency through 7=Debug)
- `--since @TIMESTAMP` -- if `query.since` is set
- `--until @TIMESTAMP` -- if `query.until` is set
- `-n LIMIT` -- if `query.limit` is set
- `--grep PATTERN` -- if `query.grep` is set

**Output parsing:**
Format: `TIMESTAMP HOSTNAME IDENT[PID]: MESSAGE`. The PID is extracted from square brackets in the IDENT field.

### Security

| Method | Source | Details |
|--------|--------|---------|
| `list_users` | `/etc/passwd`, `/etc/group` | Colon-delimited, supplementary groups from `/etc/group` |
| `list_groups` | `/etc/group` | Colon-delimited |
| `list_kernel_modules` | `/proc/modules` | Space-delimited, `used_by` is comma-separated or `-` |
| `security_status` | `/sys/fs/selinux/enforce`, `/sys/kernel/security/apparmor/profiles`, `nft`/`iptables`, `/etc/ssh/sshd_config` | Composite check |

**Security status checks:**
- **SELinux:** `/sys/fs/selinux/enforce` exists? `1`=enforcing, `0`=permissive
- **AppArmor:** `/sys/kernel/security/apparmor/profiles` exists and non-empty
- **Firewall:** tries `nft list tables` (non-empty = active), falls back to `iptables -L -n` (>8 lines = active)
- **SSH:** parses `/etc/ssh/sshd_config` for `PermitRootLogin` and `PasswordAuthentication` (case-insensitive, skips comments)

## Permission Matrix

| Operation | Unprivileged | Root Required | Notes |
|-----------|:------------:|:-------------:|-------|
| Process list/inspect | Partial | Full | Own processes always visible. Other users' `/proc/[pid]/io` may need root. |
| Process resources | Partial | Full | `/proc/[pid]/io` requires same-user or root |
| Memory info | Yes | -- | `/proc/meminfo` is world-readable |
| Process memory | Partial | Full | `/proc/[pid]/status` may restrict fields |
| Network interfaces | Yes | -- | `/sys/class/net/` is world-readable |
| Network connections | Partial | Full | PID mapping requires access to other users' `/proc/[pid]/fd/` |
| Firewall rules | No | Yes | `nft` and `iptables` require root |
| Disk/partition info | Yes | -- | `/sys/block/` and `/proc/partitions` are world-readable |
| Mount info | Yes | -- | `/proc/mounts` is world-readable |
| I/O stats | Yes | -- | `/proc/diskstats` is world-readable |
| System/kernel info | Yes | -- | `/proc/uptime`, `/proc/cpuinfo`, etc. are world-readable |
| Tunables (read) | Partial | Full | Some `/proc/sys/` files are restricted |
| Services | Yes | -- | `systemctl` status queries work unprivileged |
| Logs | Partial | Full | `journalctl` access depends on group membership (`systemd-journal`) |
| Users/groups | Yes | -- | `/etc/passwd` and `/etc/group` are world-readable |
| Kernel modules | Yes | -- | `/proc/modules` is world-readable |
| Security status | Partial | Full | SSH config may be restricted; firewall queries need root |

## Edge Cases and Known Limitations

- **Short-lived processes:** A process may exit between `/proc/` directory listing and reading its stat file. These are silently skipped.
- **CPU usage snapshot:** `cpu_info().usage_percent` is a single-point calculation from `/proc/stat`, not an interval measurement. It represents cumulative usage since boot.
- **IPv6 parsing:** IPv6 addresses from `/proc/net/if_inet6` are in a hex format without colons. The parser reconstructs standard notation.
- **Firewall detection:** If neither `nft` nor `iptables` is installed, `list_firewall_rules` returns an empty list and `security_status().firewall_active` is `false`.
- **Systemd dependency:** Service methods assume systemd. Non-systemd init systems are not supported.
- **Journal access:** Users not in the `systemd-journal` group may see limited or no log entries.
