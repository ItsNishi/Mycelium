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
│   ├── mycelium-mcp/        MCP server (Phase 2, placeholder)
│   └── mycelium-windows/    Windows backend (Phase 4, placeholder)
├── examples/
│   └── policy.toml          Example policy configuration
├── docs/                    Documentation (this folder)
└── .github/workflows/       CI pipeline
```

### Crate Responsibilities

| Crate | Description | Dependencies |
|-------|-------------|--------------|
| `mycelium-core` | Types, `Platform` trait, `MyceliumError`, policy engine. Zero dependencies by default; optional `serde` feature. | None (or `serde` opt-in) |
| `mycelium-linux` | Implements `Platform` for Linux. Reads `/proc`, `/sys`, calls `systemctl`/`journalctl`. | `mycelium-core`, `nix 0.29` |
| `mycelium-cli` | Binary `mycelium` with subcommands for every Platform method. Table and JSON output. | `mycelium-core` (serde), `mycelium-linux`, `clap 4`, `serde_json`, `toml` |
| `mycelium-mcp` | MCP server exposing Platform methods as tools. *(Phase 2, not yet implemented)* | `mycelium-core`, `rmcp` |
| `mycelium-windows` | Windows backend using WMI/winreg. *(Phase 4, not yet implemented)* | `mycelium-core` |

## Data Flow

```
                    ┌──────────────┐
                    │   AI Agent   │
                    │  (MCP client)│
                    └──────┬───────┘
                           │ JSON-RPC
                           ▼
                    ┌──────────────┐
                    │ mycelium-mcp │  (Phase 2)
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
        ┌──────────────┐  ┌──────────────┐
        │ LinuxPlatform│  │  (future)    │
        │ /proc  /sys  │  │  WinPlatform │
        │ systemctl    │  │  WMI/winreg  │
        └──────────────┘  └──────────────┘
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
| **1** | Complete | Core types, Linux backend (read ops), CLI, policy engine, 19 tests |
| **2** | Not started | MCP server via `rmcp`, tool registration, JSON-RPC transport |
| **3** | Not started | Write operations (kill, firewall, service control, sysctl) |
| **4** | Not started | Windows backend (WMI, registry, WinAPI) |
| **5** | Not started | eBPF probes (syscall tracing, network monitoring) |

### Phase 1 Scope (Current)

- 32 read-only Platform methods fully implemented on Linux
- 6 write methods defined in trait, return `Unsupported` on Linux
- Policy engine with roles, capabilities, resource filters, specificity-based evaluation
- CLI with table and JSON output for every read operation
- Policy management commands (show, list, validate)
- Integration and unit tests

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
