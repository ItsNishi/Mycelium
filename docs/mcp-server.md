# MCP Server

The `mycelium-mcp` binary exposes all 45 Platform methods as MCP tools over a JSON-RPC stdio transport. AI agents connect, discover tools via `tools/list`, and call them with typed JSON parameters. Every call is evaluated against the policy engine and logged to the audit trail.

## Building

```bash
cargo build --release -p mycelium-mcp
# Binary at target/release/mycelium-mcp
```

## Running

```bash
# Default -- no policy restrictions, agent name "default"
mycelium-mcp

# With policy file and agent identity
mycelium-mcp --config policy.toml --agent deploy-bot
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config <PATH>` | None | Path to a policy TOML config file |
| `--agent <NAME>` | `default` | Agent name for policy profile resolution |

### Transport

The server uses **stdio** transport -- JSON-RPC messages on stdin, responses on stdout. All diagnostic output (tracing, audit logs) goes to stderr. This is compatible with any MCP client that supports stdio servers.

Set the `RUST_LOG` environment variable to control log verbosity:

```bash
RUST_LOG=debug mycelium-mcp --config policy.toml --agent my-bot
```

### MCP Client Configuration

**Claude Desktop:**

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

**Claude Code (via `settings.json`):**

```json
{
  "mcpServers": {
    "mycelium": {
      "command": "/path/to/mycelium-mcp",
      "args": ["--config", "/path/to/policy.toml", "--agent", "claude-code"]
    }
  }
}
```

## Protocol

- **Protocol version:** 2024-11-05
- **Server capabilities:** `tools`
- **Library:** `rmcp` 0.17

The server responds to `initialize`, `notifications/initialized`, `tools/list`, and `tools/call`.

## Tool List

All 45 tools organized by category. Tools without parameters take an empty `arguments: {}` object. Tools with parameters require a JSON object matching the listed schema.

### Process (11 tools)

| Tool | Parameters | Description |
|------|-----------|-------------|
| `process_list` | None | List all running processes |
| `process_inspect` | `{ pid: u32 }` | Get detailed info for a single process |
| `process_resources` | `{ pid: u32 }` | Get CPU, memory, I/O usage for a process |
| `process_kill` | `{ pid: u32, signal: String }` | Send a signal (TERM, KILL, HUP, etc.) |
| `process_threads` | `{ pid: u32 }` | List threads belonging to a process |
| `process_modules` | `{ pid: u32 }` | List loaded modules (shared libraries / DLLs) for a process |
| `process_environment` | `{ pid: u32 }` | Get environment variables for a process |
| `process_privileges` | `{ pid: u32 }` | List token privileges for a process |
| `process_handles` | `{ pid: u32 }` | List open handles (files, sockets, pipes, etc.) |
| `process_pe_inspect` | `{ pid?: u32, path?: String }` | Parse PE headers (imports, exports, sections, characteristics) |
| `process_token` | `{ pid: u32 }` | Inspect token security details (integrity, groups, elevation) |

### Memory (6 tools)

| Tool | Parameters | Description |
|------|-----------|-------------|
| `memory_info` | None | System-wide memory and swap information |
| `memory_process` | `{ pid: u32 }` | Memory details for a single process |
| `memory_maps` | `{ pid: u32 }` | List memory regions (maps) for a process |
| `memory_read` | `{ pid: u32, address: u64, size: u64 }` | Read raw bytes from process virtual memory |
| `memory_write` | `{ pid: u32, address: u64, hex_data: String }` | Write raw bytes to process virtual memory |
| `memory_search` | `{ pid: u32, hex_pattern?: String, utf8_pattern?: String, utf16_pattern?: String, max_matches?: u64, context_size?: u64, permissions_filter?: String }` | Search process memory for byte patterns, UTF-8 or UTF-16 strings |

### Network (7 tools)

| Tool | Parameters | Description |
|------|-----------|-------------|
| `network_interfaces` | None | List interfaces with addresses and stats |
| `network_connections` | None | List active TCP/UDP connections |
| `network_routes` | None | List routing table entries |
| `network_ports` | None | List open (listening) ports |
| `network_firewall` | None | List firewall rules |
| `firewall_add` | `{ chain, action, protocol?, source?, destination?, port?, comment? }` | Add a firewall rule |
| `firewall_remove` | `{ rule_id: String }` | Remove a firewall rule by ID |

### Storage (4 tools)

| Tool | Parameters | Description |
|------|-----------|-------------|
| `storage_disks` | None | List physical disks |
| `storage_partitions` | None | List disk partitions |
| `storage_mounts` | None | List mounted filesystems with usage |
| `storage_io` | None | I/O statistics per block device |

### System (4 tools)

| Tool | Parameters | Description |
|------|-----------|-------------|
| `system_info` | None | Hostname, OS, architecture, uptime |
| `system_kernel` | None | Kernel version and build info |
| `system_cpu` | None | CPU model, cores, frequency, load |
| `system_uptime` | None | System uptime in seconds |

### Tuning (3 tools)

| Tool | Parameters | Description |
|------|-----------|-------------|
| `tuning_get` | `{ key: String }` | Read a kernel tunable (sysctl) |
| `tuning_list` | `{ prefix: String }` | List tunables matching a prefix |
| `tuning_set` | `{ key: String, value: String }` | Set a kernel tunable |

### Services (3 tools)

| Tool | Parameters | Description |
|------|-----------|-------------|
| `service_list` | None | List all system services |
| `service_status` | `{ name: String }` | Get status of a single service |
| `service_action` | `{ name: String, action: String }` | Perform an action (start, stop, restart, reload, enable, disable) |

### Logs (1 tool)

| Tool | Parameters | Description |
|------|-----------|-------------|
| `log_read` | `{ unit?, level?, since?, until?, limit?, grep? }` | Read journal log entries with optional filters |

`level` accepts: `emergency`, `alert`, `critical`, `error`, `warning`, `notice`, `info`, `debug`. `since`/`until` are Unix epoch seconds.

### Security (6 tools)

| Tool | Parameters | Description |
|------|-----------|-------------|
| `security_users` | None | List system user accounts |
| `security_groups` | None | List system groups |
| `security_modules` | None | List loaded kernel modules |
| `security_status` | None | Security status (SELinux, AppArmor, firewall, SSH) |
| `security_persistence` | None | Scan persistence mechanisms (Linux: cron, systemd timers, init scripts, XDG autostart, shell profiles, udev; Windows: registry, services, tasks, startup, WMI, COM) |
| `security_detect_hooks` | `{ pid: u32 }` | Detect hooks in a process (Linux: LD_PRELOAD, suspicious libraries, ptrace; Windows: inline, IAT, EAT) |

## Response Format

All successful responses return `CallToolResult` with a single text content block containing pretty-printed JSON:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\n  \"hostname\": \"myhost\",\n  \"os_name\": \"openSUSE Tumbleweed\",\n  ...}"
      }
    ],
    "isError": false
  }
}
```

Error responses set `isError: true` with a text message describing the failure.

Dry-run responses return a notice:

```
[dry-run] service_action would execute but dry-run is active
```

## Policy Enforcement

Every tool call goes through the policy engine before execution:

1. **check_policy** -- evaluates the tool name against the effective policy for the `--agent` profile
2. If **denied**, returns an error response and logs `AuditOutcome::Denied`
3. If **dry-run** mode is active, returns a dry-run notice without executing
4. If **allowed**, the tool executes and the result is logged as `Success` or `Failed`

The `--agent` flag maps to a profile name in the policy TOML. If no matching profile exists, the `default_profile` from `[global]` is used.

See [policy.md](policy.md) for the full policy engine reference.

## Audit Logging

Every tool call produces a structured audit entry logged to stderr via `tracing::info!`:

```
2026-03-01T12:00:00Z  INFO audit: agent=deploy-bot profile=deploy-bot tool=service_action
    resource=service:nginx allowed=true dry_run=false outcome=Success reason=-
```

Fields:

| Field | Description |
|-------|-------------|
| `agent` | Agent name from `--agent` flag |
| `profile` | Policy profile used (same as agent) |
| `tool` | Tool name that was called |
| `resource` | Resource context (e.g., `service:nginx`, `key:net.ipv4.ip_forward`) |
| `allowed` | Whether policy allowed the call |
| `dry_run` | Whether dry-run mode was active |
| `outcome` | `Success`, `Denied`, `DryRun`, or `Failed` |
| `reason` | Denial reason or error message |

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    mycelium-mcp                       │
│                                                      │
│  main.rs          lib.rs            tools/mod.rs     │
│  ┌──────────┐    ┌──────────────┐  ┌──────────────┐ │
│  │ CLI args │───▶│ MCP Service  │──│ Tool Router  │ │
│  │ stdio()  │    │ check_policy │  │ 45 #[tool]   │ │
│  └──────────┘    │ log_success  │  │ methods      │ │
│                  │ log_failure  │  └──────┬───────┘ │
│                  └──────┬───────┘         │         │
│                         │                 │         │
│           ┌─────────────┼─────────────────┘         │
│           │             │                           │
│           ▼             ▼                           │
│   ┌──────────────┐  ┌──────────────┐               │
│   │   Policy     │  │  Platform    │               │
│   │   (core)     │  │  (linux)     │               │
│   └──────────────┘  └──────────────┘               │
│                                                     │
│   ┌──────────────┐                                  │
│   │  AuditLog    │  (StderrAuditLog via tracing)    │
│   └──────────────┘                                  │
└──────────────────────────────────────────────────────┘
```

### Handler Pattern

Every tool handler follows the same pattern:

```rust
pub async fn handle_example(svc: &MyceliumMcpService, req: Request)
    -> Result<CallToolResult, McpError>
{
    // 1. Policy check
    if let Some(result) = svc.check_policy("tool_name", resource.as_deref()) {
        return result;
    }
    // 2. Dry-run check
    if svc.is_dry_run() {
        return dry_run_text("tool_name");
    }
    // 3. Execute on blocking thread
    let platform = svc.platform();
    match tokio::task::spawn_blocking(move || platform.method()).await {
        Ok(Ok(data)) => {
            svc.log_success("tool_name", resource.as_deref());
            ok_json(&data)
        }
        Ok(Err(e)) => {
            svc.log_failure("tool_name", &e.to_string());
            err_text(&e.to_string())
        }
        Err(e) => err_text(&format!("task join error: {e}")),
    }
}
```

### Request Structs

Tool parameters use structs with `serde::Deserialize` and `schemars::JsonSchema` derives. The `schemars` descriptions become the tool's JSON Schema in MCP, which AI agents use to understand parameter semantics:

```rust
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct KeyRequest {
    #[schemars(description = "Sysctl key (e.g. net.ipv4.ip_forward)")]
    pub key: String,
}
```

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `mycelium-core` | workspace | Types, Platform trait, policy engine, TOML config |
| `mycelium-linux` | workspace | Linux Platform implementation |
| `rmcp` | 0.17 | MCP server framework (tool macros, JSON-RPC, stdio transport) |
| `tokio` | 1 | Async runtime for MCP server |
| `serde` / `serde_json` | 1 | JSON serialization |
| `schemars` | 1 | JSON Schema generation for tool parameters |
| `clap` | 4 | CLI argument parsing |
| `tracing` / `tracing-subscriber` | 0.1 / 0.3 | Structured logging to stderr |
| `anyhow` | 1 | Error handling in main |
