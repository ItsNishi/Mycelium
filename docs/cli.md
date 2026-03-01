# CLI Reference

The `mycelium` binary provides command-line access to all Platform read operations, policy management, and (in future phases) write operations.

## Building

```bash
cargo build --release -p mycelium-cli
# Binary at target/release/mycelium
```

## Global Flags

| Flag | Description |
|------|-------------|
| `--json` | Output as pretty-printed JSON instead of table format |
| `--dry-run` | Prevent write operations (forces dry-run mode) |
| `--config <PATH>` | Path to a policy TOML config file |

Global flags must appear before the subcommand:

```bash
mycelium --json process list
mycelium --dry-run --config policy.toml service action nginx restart
```

## Commands

### Process

#### `mycelium process list`

List all running processes.

```
PID    PPID   NAME             STATE      USER     THREADS  CPU%   MEMORY       COMMAND
1      0      systemd          Sleeping   root     1        0.00   12648448     /sbin/init
452    1      systemd-journal  Sleeping   root     1        0.00   41943040     /usr/lib/systemd/systemd-journald
1823   1      sshd             Sleeping   root     1        0.00   6291456      sshd: /usr/sbin/sshd
```

```bash
mycelium --json process list
```

```json
[
  {
    "pid": 1,
    "ppid": 0,
    "name": "systemd",
    "state": "Sleeping",
    "user": "root",
    "uid": 0,
    "threads": 1,
    "cpu_percent": 0.0,
    "memory_bytes": 12648448,
    "command": "/sbin/init",
    "start_time": 1709312400
  }
]
```

#### `mycelium process inspect <PID>`

Get detailed info for a single process.

```bash
mycelium process inspect 1
```

#### `mycelium process resources <PID>`

Get resource usage for a single process.

```
PID    CPU%   MEMORY       MEM%   VIRTUAL      FDS    THREADS  READ_BYTES   WRITE_BYTES
1823   0.10   6291456      0.04   134217728    24     1        1048576      524288
```

---

### Memory

#### `mycelium memory info`

Show system-wide memory information.

```
TOTAL          USED           AVAILABLE      FREE           BUFFERS        CACHED
16777216000    8388608000     10737418240    4294967296     536870912      3758096384

SWAP_TOTAL     SWAP_USED      SWAP_FREE
4294967296     0              4294967296
```

#### `mycelium memory process <PID>`

Show memory details for a single process.

```
PID    RSS            VIRTUAL        SHARED         TEXT           DATA
1823   6291456        134217728      2097152        524288         8388608
```

---

### Network

#### `mycelium network interfaces`

List network interfaces with statistics.

```
NAME     MAC                IPV4             IPV6                       MTU    STATE  RX_BYTES     TX_BYTES
eth0     aa:bb:cc:dd:ee:ff  192.168.1.100    fe80::1                    1500   Up     104857600    52428800
lo       00:00:00:00:00:00  127.0.0.1        ::1                        65536  Up     1048576      1048576
```

#### `mycelium network connections`

List active TCP and UDP connections.

```
PROTO  LOCAL_ADDR       LOCAL_PORT  REMOTE_ADDR      REMOTE_PORT  STATE         PID    PROCESS
Tcp    192.168.1.100    22          192.168.1.50     54321        Established   1823   sshd
Tcp    0.0.0.0          80          0.0.0.0          0            Listen        2048   nginx
```

#### `mycelium network routes`

List the routing table.

```
DESTINATION    GATEWAY        NETMASK          INTERFACE  METRIC  FLAGS
0.0.0.0        192.168.1.1    0.0.0.0          eth0       100     UG
192.168.1.0    0.0.0.0        255.255.255.0    eth0       100     U
```

#### `mycelium network ports`

List open (listening) ports.

```
PROTO  ADDRESS    PORT  PID    PROCESS
Tcp    0.0.0.0    22    1823   sshd
Tcp    0.0.0.0    80    2048   nginx
Udp    0.0.0.0    53    1456   systemd-resolve
```

#### `mycelium network firewall`

List firewall rules (nftables or iptables).

```
ID     CHAIN    PROTO  SOURCE           DEST             PORT   ACTION  COMMENT
1      input    tcp    0.0.0.0/0        0.0.0.0/0        22     Accept  SSH access
2      input    tcp    192.168.1.0/24   0.0.0.0/0        80     Accept  HTTP from LAN
```

---

### Storage

#### `mycelium storage disks`

List physical disks.

```
NAME  MODEL              SERIAL           SIZE             REMOVABLE  ROTATIONAL
sda   Samsung SSD 870    S1234567890      500107862016     false      false
sdb   WDC WD40EFAX       WD-12345678      4000787030016    false      true
```

#### `mycelium storage partitions`

List partitions.

```
NAME   PARENT  SIZE             FILESYSTEM  MOUNT_POINT  LABEL    UUID
sda1   sda     536870912        vfat        /boot/efi    EFI      ABCD-1234
sda2   sda     499571441664     btrfs       /            root     abcd1234-5678
```

#### `mycelium storage mounts`

List mounted filesystems (pseudo-filesystems filtered out).

```
DEVICE   MOUNT_PATH   FILESYSTEM  TOTAL          USED           AVAILABLE      USE%
/dev/sda2  /          btrfs       499571441664   214748364800   284823076864   43.0
/dev/sda1  /boot/efi  vfat        536870912      33554432       503316480      6.3
```

#### `mycelium storage io`

Show I/O statistics per block device.

```
DEVICE  READS      WRITES     READ_BYTES       WRITE_BYTES      IO_PENDING  IO_TIME_MS
sda     1234567    987654     63216549888      50536382464      0           12345678
```

---

### System

#### `mycelium system info`

Show system information.

```
HOSTNAME       OS_NAME        OS_VERSION               ARCHITECTURE  UPTIME_SECONDS  BOOT_TIME
myhost         openSUSE       Tumbleweed 20260228      x86_64        86400           1709312400
```

#### `mycelium system kernel`

Show kernel information.

```
RELEASE              VERSION                                    ARCHITECTURE  COMMAND_LINE
6.19.2-1-default     #1 SMP PREEMPT_DYNAMIC ... (trimmed)      x86_64        root=UUID=... quiet splash
```

#### `mycelium system cpu`

Show CPU information.

```
MODEL_NAME                      PHYSICAL  LOGICAL  FREQ_MHZ  CACHE_KB  LOAD_AVG         USAGE%
AMD Ryzen 7 5800X               8         16       3800.0    32768     0.42 0.38 0.35    12.5
```

#### `mycelium system uptime`

Print system uptime in seconds.

```
86400
```

---

### Tuning

#### `mycelium tuning get <KEY>`

Read a single kernel tunable.

```bash
mycelium tuning get net.ipv4.ip_forward
```

```
KEY                      VALUE
net.ipv4.ip_forward      1
```

#### `mycelium tuning list [PREFIX]`

List tunables matching a prefix. Lists all if no prefix given.

```bash
mycelium tuning list net.ipv4
```

```
KEY                              VALUE
net.ipv4.ip_forward              1
net.ipv4.tcp_syncookies          1
net.ipv4.conf.all.forwarding     0
```

---

### Service

#### `mycelium service list`

List all known services.

```
NAME                STATE       ENABLED  PID    DESCRIPTION
sshd.service        Running     true     1823   OpenSSH Daemon
nginx.service       Running     true     2048   The nginx HTTP and reverse proxy server
postgresql.service  Stopped     true            PostgreSQL database server
```

#### `mycelium service status <NAME>`

Get status of a single service.

```bash
mycelium service status sshd
```

```
NAME            DISPLAY_NAME     STATE    ENABLED  PID    DESCRIPTION
sshd.service    OpenSSH Daemon   Running  true     1823   OpenSSH Daemon
```

---

### Log

#### `mycelium log [FLAGS]`

Read journal log entries. This command uses flags directly (no subcommand).

| Flag | Short | Description |
|------|-------|-------------|
| `--unit <UNIT>` | `-u` | Filter by systemd unit |
| `--level <LEVEL>` | `-l` | Minimum log level |
| `--limit <N>` | `-n` | Maximum entries (default: 50) |
| `--grep <PATTERN>` | | Filter messages containing pattern |
| `--since <TIMESTAMP>` | | Unix timestamp lower bound |
| `--until <TIMESTAMP>` | | Unix timestamp upper bound |

Log levels: `emergency`, `alert`, `critical`, `error`, `warning`, `notice`, `info`, `debug`

```bash
mycelium log -u sshd -l warning -n 10
```

```
TIMESTAMP    LEVEL    UNIT   PID    MESSAGE
1709398800   Warning  sshd   1823   Failed password for root from 10.0.0.5 port 44312 ssh2
1709398802   Warning  sshd   1823   Failed password for root from 10.0.0.5 port 44312 ssh2
```

---

### Security

#### `mycelium security users`

List system user accounts.

```
NAME     UID    GID    HOME             SHELL           GROUPS
root     0      0      /root            /bin/bash        root
nishi    1000   1000   /home/nishi      /bin/bash        users,wheel,docker
```

#### `mycelium security groups`

List system groups.

```
NAME     GID    MEMBERS
root     0      root
wheel    10     nishi
docker   971    nishi
```

#### `mycelium security modules`

List loaded kernel modules.

```
NAME              SIZE_BYTES  STATE  USED_BY
nvidia            62914560    Live   nvidia_modeset,nvidia_uvm
btrfs             1572864     Live
```

#### `mycelium security status`

Show security status overview.

```
SELINUX          APPARMOR         FIREWALL  ROOT_LOGIN  PASSWORD_SSH
disabled         disabled         true      false       true
```

---

### Policy

#### `mycelium policy show [--profile <NAME>]`

Show the effective policy for a profile. Uses the default profile if `--profile` is omitted.

```bash
mycelium --config policy.toml policy show --profile operator
```

#### `mycelium policy list`

List all defined profiles.

```bash
mycelium --config policy.toml policy list
```

#### `mycelium policy validate <PATH>`

Validate a policy TOML file and report errors.

```bash
mycelium policy validate examples/policy.toml
```

---

## Output Formatting

### Table Format (default)

- Columns are separated by whitespace
- Byte values shown as raw integers (use `--json` for structured data)
- Long strings truncated to fit terminal width
- Uptime formatted as `Xd Xh Xm` where applicable

### JSON Format (`--json`)

- Pretty-printed via `serde_json`
- All types serialize using their `serde` derives
- Arrays for list commands, single objects for inspect/info commands
- Enum variants serialize as strings (e.g., `"Sleeping"`, `"Tcp"`, `"Accept"`)

### Formatting Helpers

| Helper | Description | Example |
|--------|-------------|---------|
| `human_bytes(n)` | Bytes to KiB/MiB/GiB/TiB | `1073741824` -> `1.0 GiB` |
| `human_uptime(n)` | Seconds to days/hours/minutes | `90061` -> `1d 1h 1m` |
| `truncate(s, n)` | Truncate with ellipsis | `"very long..."` |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Runtime error (permission denied, not found, parse error, etc.) |
