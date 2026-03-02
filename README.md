# 🍄 Mycelium

**Structured, typed, cross-platform access to kernel-level OS information -- built for AI agents.**

Like fungal mycelium threading through soil to surface nutrients, Mycelium threads through `/proc`, `/sys`, and OS APIs to surface clean, structured system data. AI agents connect via MCP and get typed JSON instead of parsing raw shell output.

![License](https://img.shields.io/badge/license-MIT-blue)
![Rust](https://img.shields.io/badge/rust-2024_edition-orange)

---

## ✨ Features

- 🔍 **49 tools** across 10 categories (process, memory, network, storage, system, tuning, services, logs, security, probes)
- 🛡️ **Policy engine** with role presets, capability groups, resource filters, and specificity-based evaluation
- 📊 **Dual output** -- human-readable tables or structured JSON
- 🧩 **Modular workspace** -- zero-dependency core, pluggable OS backends
- 🔒 **Audit logging** with per-agent tracking and dry-run mode
- ⚡ **Stateless & synchronous** -- every call reads fresh kernel data, no caching

## 📦 Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   AI Agent   │     │   mycelium   │     │   Your App   │
│  (MCP client)│     │     CLI      │     │  (Rust lib)  │
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │ JSON-RPC           │ direct             │ direct
       ▼                    ▼                    ▼
┌──────────────────────────────────────────────────────┐
│                   mycelium-core                      │
│          Platform trait · Policy · Types              │
└───────────────────────┬──────────────────────────────┘
                        │
              ┌─────────┴─────────┐
              ▼                   ▼
      ┌──────────────┐    ┌──────────────┐
      │ mycelium-    │    │ mycelium-    │
      │ linux        │    │ windows      │
      │ /proc  /sys  │    │ WMI  winreg  │
      └──────────────┘    └──────────────┘
            ✅                  ✅
```

| Crate | Description |
|-------|-------------|
| `mycelium-core` | Types, `Platform` trait, errors, policy engine. Zero dependencies by default. |
| `mycelium-ebpf-common` | Shared `#[repr(C)]` event types for eBPF programs (`#![no_std]`) |
| `mycelium-ebpf` | eBPF programs for syscall tracing and network monitoring (not a workspace member) |
| `mycelium-linux` | Linux backend -- `/proc`, `/sys`, `systemctl`, `journalctl`, eBPF (optional) |
| `mycelium-cli` | CLI binary with table/JSON output for every operation |
| `mycelium-mcp` | MCP server exposing all 49 tools to AI agents via JSON-RPC over stdio |
| `mycelium-windows` | Windows backend (sysinfo, WinAPI, WMI, NetAPI32) |

## 🚀 Quick Start

### Build

```bash
# CLI
cargo build --release -p mycelium-cli

# MCP server
cargo build --release -p mycelium-mcp
```

### MCP Server

Start the MCP server on stdio for AI agent integration:

```bash
# Default (no policy restrictions)
mycelium-mcp

# With policy and agent identity
mycelium-mcp --config policy.toml --agent deploy-bot
```

The server speaks JSON-RPC over stdin/stdout (MCP protocol 2024-11-05). All 49 tools are registered and discoverable via `tools/list`. Policy enforcement and audit logging apply to every tool call.

**Claude Desktop / MCP client config:**

```json
{
  "mcpServers": {
    "mycelium": {
      "command": "/path/to/mycelium-mcp",
      "args": ["--config", "/path/to/policy.toml", "--agent", "claude"]
    }
  }
}
```

### CLI

```bash
mycelium system info
```

### Run

```bash
# System overview
mycelium system info
mycelium system cpu
mycelium memory info

# Processes
mycelium process list
mycelium process inspect 1
mycelium process resources 1823

# Network
mycelium network interfaces
mycelium network connections
mycelium network ports

# Storage
mycelium storage disks
mycelium storage mounts
mycelium storage io

# Services & logs
mycelium service list
mycelium service status sshd
mycelium log -u sshd -l warning -n 10

# Security
mycelium security users
mycelium security modules
mycelium security status

# Kernel tunables
mycelium tuning get net.ipv4.ip_forward
mycelium tuning list net.ipv4
```

### JSON Output

Add `--json` before any command for structured output:

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

## 🛡️ Policy Engine

Control what each agent can do with role-based presets and fine-grained rules.

```toml
# policy.toml
[global]
default_profile = "operator"

[[global.rules]]
action = "allow"
target = "all"

[[global.rules]]
action = "deny"
target = { capability = "probe_manage" }
reason = "eBPF probes disabled globally"

# Full admin for trusted agents
[profiles.claude-code]
role = "admin"

# Restricted bot -- can only restart specific services
[profiles.deploy-bot]
role = "operator"

[[profiles.deploy-bot.rules]]
action = "allow"
target = { tool = "service_action" }
filter = { service_names = ["nginx", "postgresql", "redis"] }

[[profiles.deploy-bot.rules]]
action = "deny"
target = { tool = "service_action" }
reason = "Only nginx, postgresql, redis allowed"

# Read-only monitoring
[profiles.monitor-bot]
role = "read-only"
dry_run = true
```

**Roles:** `admin` (full access) · `operator` (reads + process/service management) · `read-only` (reads only) · `custom` (fully user-defined)

**Capabilities:** `process_manage` · `kernel_tune` · `firewall_manage` · `service_manage` · `probe_manage` · `policy_manage` · `memory_access`

```bash
mycelium --config policy.toml policy show --profile deploy-bot
mycelium --config policy.toml policy list
mycelium policy validate policy.toml
```

## 📋 Command Reference

| Category | Commands |
|----------|----------|
| **Process** | `list`, `inspect <PID>`, `resources <PID>`, `threads <PID>`, `modules <PID>`, `privileges <PID>`, `handles <PID>`, `pe-inspect`, `token <PID>` |
| **Memory** | `info`, `process <PID>`, `maps <PID>`, `read`, `write`, `search` |
| **Network** | `interfaces`, `connections`, `routes`, `ports`, `firewall` |
| **Storage** | `disks`, `partitions`, `mounts`, `io` |
| **System** | `info`, `kernel`, `cpu`, `uptime` |
| **Tuning** | `get <KEY>`, `list [PREFIX]` |
| **Service** | `list`, `status <NAME>` |
| **Log** | `-u UNIT`, `-l LEVEL`, `-n LIMIT`, `--grep PATTERN`, `--since TS`, `--until TS` |
| **Security** | `users`, `groups`, `modules`, `status`, `persistence`, `detect-hooks <PID>` |
| **Policy** | `show [--profile NAME]`, `list`, `validate <PATH>` |
| **Probe** | `attach --type <TYPE>`, `detach <HANDLE>`, `list`, `events <HANDLE> [--follow] [--limit N]` |

**Global flags:** `--json` · `--dry-run` · `--config <PATH>`

## 🗺️ Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| **1** | ✅ Complete | Core types, Linux backend (read ops), CLI, policy engine |
| **2** | ✅ Complete | MCP server (35 tools, JSON-RPC stdio, policy enforcement, audit logging) |
| **3** | ✅ Complete | Write operations (kill, firewall, service control, sysctl, direct memory access) |
| **4** | ✅ Complete | Windows backend (sysinfo, WinAPI, WMI, NetAPI32, SCM, token APIs) |
| **4.5** | ✅ Complete | Security research (handles, PE parsing, token inspection, persistence, hook detection, memory search) |
| **5** | ✅ Complete | Linux backend feature parity (threads, modules, capabilities, FD handles, token inspection, memory search, persistence scanning, hook detection) |
| **6** | ✅ Complete | eBPF probes (syscall tracing, network monitoring via aya, feature-gated) |

## 🛠️ Development

```bash
# Build
cargo build --workspace

# Test (202 passing)
cargo test --workspace

# Lint
cargo clippy --workspace -- -D warnings

# Format
cargo fmt --all -- --check
```

**Requirements:** Rust 2024 edition (rustc 1.85+), Linux or Windows

**eBPF probes (optional):** Requires `bpf-linker`, nightly Rust, kernel 5.8+, root/CAP_BPF at runtime:

```bash
cargo install bpf-linker
cargo build --workspace --features mycelium-linux/ebpf
```

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | Design overview, data flow, workspace layout, design decisions |
| [MCP Server](docs/mcp-server.md) | MCP server setup, tool list, policy integration, audit logging |
| [CLI Reference](docs/cli.md) | Every command with flags, arguments, and output examples |
| [Policy Engine](docs/policy.md) | Rules, roles, capabilities, filters, evaluation algorithm |
| [Platform API](docs/platform-api.md) | All 46 trait methods with signatures and error handling |
| [Type Reference](docs/types.md) | Every struct, enum, and field across all modules |
| [Linux Backend](docs/linux-backend.md) | Data sources, `/proc` paths, permission matrix, limitations |
| [Windows Backend](docs/windows-backend.md) | Data sources, API mapping, size limits, permission matrix |
| [Development Guide](docs/development.md) | Build, test, conventions, adding methods and backends |

## 📄 License

[MIT](LICENSE)
