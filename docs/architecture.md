# Architecture

Mycelium is a Rust library + CLI + MCP server that provides structured, typed, cross-platform access to kernel-level OS information. AI agents connect via MCP and get clean JSON responses instead of parsing raw shell output.

The name reflects the design: like fungal mycelium threading through soil to surface nutrients, Mycelium threads through `/proc`, `/sys`, and OS APIs to surface structured system data.

## Workspace Layout

```
Mycelium/
├── crates/
│   ├── mycelium-core/       Core types, traits, errors, policy engine
│   ├── mycelium-linux/      Linux backend (/proc, /sys, nix)
│   ├── mycelium-cli/        CLI binary (clap)
│   ├── mycelium-mcp/        MCP server (43 tools, rmcp 0.17, stdio)
│   └── mycelium-windows/    Windows backend (sysinfo, WinAPI, WMI)
├── examples/
│   └── policy.toml          Example policy configuration
├── docs/                    Documentation (this folder)
└── .github/workflows/       CI pipeline
```

### Crate Responsibilities

| Crate | Description | Dependencies |
|-------|-------------|--------------|
| `mycelium-core` | Types, `Platform` trait, `MyceliumError`, policy engine. Zero dependencies by default; optional `serde` and `toml` features. | None (or `serde`/`toml` opt-in) |
| `mycelium-linux` | Implements `Platform` for Linux. Reads `/proc`, `/sys`, calls `systemctl`/`journalctl`. | `mycelium-core`, `nix 0.29` |
| `mycelium-cli` | Binary `mycelium` with subcommands for every Platform method. Table and JSON output. | `mycelium-core` (serde, toml), `mycelium-linux`, `clap 4`, `serde_json` |
| `mycelium-mcp` | MCP server exposing all 43 tools via JSON-RPC stdio transport. | `mycelium-core` (serde, toml), `mycelium-linux`, `rmcp 0.17`, `tokio`, `clap 4`, `schemars` |
| `mycelium-windows` | Windows backend using sysinfo, WinAPI, WMI, NetAPI32, and winreg. Implements all 46 Platform methods. | `mycelium-core`, `sysinfo`, `windows 0.61`, `wmi`, `winreg` |

## Data Flow

```
                    ┌──────────────┐
                    │   AI Agent   │
                    │  (MCP client)│
                    └──────┬───────┘
                           │ JSON-RPC
                           ▼
                    ┌──────────────┐
                    │ mycelium-mcp │
                    │  MCP server  │
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
      ┌──────────┐  ┌──────────┐  ┌──────────┐
      │  Policy  │  │ Platform │  │  Audit   │
      │  Engine  │  │  trait   │  │   Log    │
      └──────────┘  └────┬─────┘  └──────────┘
                         │
                ┌────────┴────────┐
                │                 │
                ▼                 ▼
        ┌──────────────┐  ┌────────────────┐
        │ LinuxPlatform│  │WindowsPlatform │
        │ /proc  /sys  │  │ sysinfo WinAPI │
        │ systemctl    │  │ WMI  winreg    │
        └──────────────┘  └────────────────┘
```

For the CLI path, `mycelium-cli` calls `Platform` methods directly (no MCP layer):

```
mycelium process list --json
    │
    ▼
Cli struct (clap) ──► Command dispatch ──► LinuxPlatform::list_processes()
    │                                            │
    ▼                                            ▼
OutputFormat::Json ◄──────────── Vec<ProcessInfo>
    │
    ▼
  stdout
```

## Phase Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| **1** | Complete | Core types, Linux backend (read ops), CLI, policy engine |
| **2** | Complete | MCP server (35 tools, JSON-RPC stdio, policy enforcement, audit logging) |
| **3** | Complete | Write operations (kill, firewall, service control, sysctl, direct memory access) |
| **4** | Complete | Windows backend (sysinfo, WinAPI, WMI, NetAPI32, SCM, token APIs) |
| **4.5** | Complete | Security research features (handles, PE parsing, token inspection, persistence scanning, hook detection, memory pattern search) |
| **5** | Not started | eBPF probes (syscall tracing, network monitoring) |

### Phase 1 Scope

- 46 Platform methods (35 read + 7 write + 4 sensitive) — Linux implements core set, Windows implements all
- All write and sensitive operations gated by policy capabilities
- Policy engine with roles, capabilities, resource filters, specificity-based evaluation
- CLI with table and JSON output for every read operation
- Policy management commands (show, list, validate)
- 213+ unit tests (policy evaluation, TOML config parsing, Windows backend helpers)

### Phase 2 Scope

- MCP server binary (`mycelium-mcp`) using `rmcp` 0.17 with stdio transport
- All 35 Platform methods registered as MCP tools with JSON schemas via `schemars`
- Per-agent policy enforcement with `--agent` and `--config` flags
- Audit logging to stderr via `tracing`
- Policy TOML parsing extracted to `mycelium-core` behind optional `toml` feature
- Synchronous Platform calls wrapped with `tokio::task::spawn_blocking`

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Zero-dependency core | `mycelium-core` compiles without `std` dependencies beyond `core` and `std::io`. Backends and serialization are opt-in. |
| Synchronous Platform trait | `/proc` reads are kernel-backed memory operations (microseconds). The async MCP layer wraps calls with `spawn_blocking`. |
| Specificity-based policy | More specific rules always win regardless of order. Filtered rules get a +4 bonus. This prevents accidental overrides. |
| Separate ProbePlatform trait | eBPF probes are Linux-only. Keeping them in a separate trait means Windows backends don't need to stub 4 extra methods. |
| `cfg_attr` serde derives | Core types only derive `Serialize`/`Deserialize` behind the `serde` feature flag. The Linux backend doesn't pay for serde. |
| Stateless backends | `LinuxPlatform` is a zero-sized struct with no fields. Every call reads fresh data from the kernel. No caching, no stale state. |
| Custom error enum | Manual `Display` and `Error` impls instead of `thiserror` to maintain the zero-dependency guarantee in core. |
| Edition 2024 | Uses the latest Rust edition for the newest language features. |
