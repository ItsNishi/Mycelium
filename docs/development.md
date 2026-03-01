# Development Guide

## Prerequisites

- **Rust:** Edition 2024 (requires rustc 1.85+)
- **OS:** Linux (for running the Linux backend and integration tests)
- **Optional:** `systemctl`, `journalctl` (for service and log tests)

## Building

```bash
# Build all crates
cargo build --workspace

# Build release (optimized, stripped)
cargo build --release --workspace

# Build just the CLI
cargo build -p mycelium-cli
```

Release profile settings (from workspace `Cargo.toml`):

```toml
[profile.release]
opt-level = "z"       # Optimize for size
lto = true            # Link-time optimization
strip = true          # Strip debug symbols
panic = "abort"       # No unwinding
```

## Testing

```bash
# Run all tests
cargo test --workspace

# Run tests for a specific crate
cargo test -p mycelium-core
cargo test -p mycelium-linux

# Run a specific test
cargo test -p mycelium-core -- policy::tests::read_only_denies_writes
```

### Test Structure

- **Unit tests:** `#[cfg(test)] mod tests` blocks within source files
- **Integration tests:** `tests/` directories within each crate
- **Policy evaluation tests:** 13 tests in `mycelium-core/src/policy/mod.rs` covering roles, specificity, filters, dry-run, and overrides
- **Policy config tests:** 6 tests in `mycelium-core/src/policy/config.rs` covering TOML parsing, profile resolution, and filters

### What's Tested

| Area | Tests | Location |
|------|-------|----------|
| Default policy (allow all) | 1 | `policy/mod.rs` |
| ReadOnly role | 1 | `policy/mod.rs` |
| Operator role | 1 | `policy/mod.rs` |
| Admin role | 1 | `policy/mod.rs` |
| Profile overrides | 1 | `policy/mod.rs` |
| Service name filter | 1 | `policy/mod.rs` |
| Tunable prefix filter | 1 | `policy/mod.rs` |
| Dry-run propagation | 1 | `policy/mod.rs` |
| Global dry-run override | 1 | `policy/mod.rs` |
| Unknown profile fallback | 1 | `policy/mod.rs` |
| Last rule wins | 1 | `policy/mod.rs` |
| Specificity ordering | 1 | `policy/mod.rs` |
| Global rules combine with profile | 1 | `policy/mod.rs` |
| TOML parsing (full sample) | 1 | `policy/config.rs` |
| Admin overrides global deny | 1 | `policy/config.rs` |
| Service name filter (TOML) | 1 | `policy/config.rs` |
| Tunable prefix filter (TOML) | 1 | `policy/config.rs` |
| Restricted bot read-only dry-run | 1 | `policy/config.rs` |
| Unknown agent fallback (TOML) | 1 | `policy/config.rs` |

## Code Conventions

### Formatting

- **Indentation:** Tabs (configured in `rustfmt.toml` if present)
- **Braces:** Same-line opening braces (Rust convention, not Allman)
- **Line length:** Soft limit 100, hard limit 120

### Naming

- `PascalCase` for types, traits, enum variants
- `snake_case` for functions, methods, variables, modules
- Constant naming follows Rust convention (`UPPER_SNAKE_CASE`)

### Error Handling

- All fallible operations return `mycelium_core::error::Result<T>`
- Custom `MyceliumError` enum with manual `Display` and `Error` impls
- `From<std::io::Error>` impl for automatic `?` conversion
- No `thiserror` or `anyhow` -- zero-dependency core

### Serde

Core types use conditional serde derives:

```rust
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
```

This keeps `mycelium-core` dependency-free by default. The CLI and MCP server enable serde and toml:

```toml
mycelium-core = { path = "../mycelium-core", features = ["serde", "toml"] }
```

The `toml` feature enables TOML policy config parsing (`policy::config` module) and implies `serde`.

### Doc Comments

Public API items use `///` doc comments. Internal implementation details use `//`.

## Linting

```bash
# Run clippy with warnings as errors
cargo clippy --workspace -- -D warnings

# Check formatting
cargo fmt --all -- --check

# Fix formatting
cargo fmt --all
```

## Adding a New Platform Method

To add a new read method (e.g., `list_containers`):

1. **Define the type** in `crates/mycelium-core/src/types/`. Create a new module or add to an existing one:

```rust
// types/container.rs
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub state: String,
    pub image: String,
}
```

2. **Export the type** from `crates/mycelium-core/src/types/mod.rs`:

```rust
pub mod container;
pub use container::*;
```

3. **Add the method** to the `Platform` trait in `crates/mycelium-core/src/platform.rs`:

```rust
/// List running containers.
fn list_containers(&self) -> Result<Vec<ContainerInfo>>;
```

4. **Implement on Linux** in `crates/mycelium-linux/src/`. Create a module or add to an existing one, then implement in `platform.rs`:

```rust
fn list_containers(&self) -> Result<Vec<ContainerInfo>> {
    container::list_containers()
}
```

5. **Add a CLI command** in `crates/mycelium-cli/src/commands/`. Create a new module, add the `Command` variant, implement `TableDisplay`, and wire it into `main.rs`.

6. **Add an MCP tool** in `crates/mycelium-mcp/src/tools/`. Either add to an existing category file or create a new one. Register the `#[tool]` method in `tools/mod.rs` and create a request struct with `schemars::JsonSchema` derive if the tool takes parameters.

7. **Add tests** in the implementing crate.

8. **If it's a write operation**, add it to the appropriate `Capability` in `capability.rs` and update role presets if needed.

## Adding a New Backend

To add support for a new OS (e.g., macOS):

1. **Create the crate:**

```bash
cargo new crates/mycelium-macos --lib
```

2. **Add workspace member** in root `Cargo.toml`:

```toml
members = [
    "crates/mycelium-core",
    "crates/mycelium-linux",
    "crates/mycelium-macos",    # new
    "crates/mycelium-cli",
]
```

3. **Depend on mycelium-core:**

```toml
[dependencies]
mycelium-core = { path = "../mycelium-core" }
```

4. **Create the platform struct** and implement `Platform`:

```rust
pub struct MacPlatform;

impl Platform for MacPlatform {
    fn list_processes(&self) -> Result<Vec<ProcessInfo>> {
        // macOS implementation using sysctl, libproc, etc.
    }
    // ... all 32 methods
}
```

5. **Add conditional compilation** in the CLI:

```rust
#[cfg(target_os = "macos")]
use mycelium_macos::MacPlatform;
```

6. **Update CI** to include macOS in the test matrix.

## CI Pipeline

GitHub Actions runs on push to `main` and pull requests. Four jobs:

| Job | Runner | Steps |
|-----|--------|-------|
| **Check** | ubuntu-latest, windows-latest | `cargo check --workspace`, `cargo build --workspace` |
| **Test** | ubuntu-latest | `cargo test --workspace` |
| **Clippy** | ubuntu-latest | `cargo clippy --workspace -- -D warnings` |
| **Format** | ubuntu-latest | `cargo fmt --all -- --check` |

All jobs use:
- `actions/checkout@v4`
- `dtolnay/rust-toolchain@stable`
- `Swatinem/rust-cache@v2`

The Check job runs on both Ubuntu and Windows to verify cross-platform compilation (Windows backend is Phase 4, but the core crate must compile everywhere).

## Project Structure

```
Mycelium/
├── Cargo.toml                    Workspace definition
├── CLAUDE.md                     Project conventions
├── crates/
│   ├── mycelium-core/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs            Module re-exports
│   │       ├── error.rs          MyceliumError enum
│   │       ├── audit.rs          Audit types and trait
│   │       ├── platform.rs       Platform + ProbePlatform traits
│   │       ├── policy/
│   │       │   ├── mod.rs        Policy, EffectivePolicy, evaluation
│   │       │   ├── config.rs     TOML parsing (behind "toml" feature)
│   │       │   ├── rule.rs       PolicyRule, RuleTarget, ResourceFilter
│   │       │   ├── profile.rs    Profile, Role presets
│   │       │   └── capability.rs Capability enum and tool mapping
│   │       └── types/
│   │           ├── mod.rs        Re-exports
│   │           ├── process.rs    ProcessInfo, ProcessState, Signal, ...
│   │           ├── memory.rs     MemoryInfo, SwapInfo
│   │           ├── network.rs    NetworkInterface, Connection, Route, ...
│   │           ├── storage.rs    DiskInfo, Partition, MountPoint, IoStats
│   │           ├── system.rs     SystemInfo, KernelInfo, CpuInfo
│   │           ├── service.rs    ServiceInfo, ServiceState, ServiceAction
│   │           ├── security.rs   UserInfo, GroupInfo, KernelModule, ...
│   │           ├── log.rs        LogEntry, LogLevel, LogQuery
│   │           ├── probe.rs      ProbeHandle, ProbeConfig, ProbeEvent
│   │           └── tuning.rs     TunableParam, TunableValue
│   ├── mycelium-linux/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs            Module re-exports
│   │       ├── platform.rs       LinuxPlatform struct + trait impl
│   │       ├── process.rs        /proc/[pid]/ parsing
│   │       ├── memory.rs         /proc/meminfo parsing
│   │       ├── network.rs        /proc/net/, /sys/class/net/ parsing
│   │       ├── storage.rs        /sys/block/, /proc/diskstats parsing
│   │       ├── system.rs         uname, /proc/cpuinfo, /proc/loadavg
│   │       ├── tuning.rs         /proc/sys/ access
│   │       ├── service.rs        systemctl wrapper
│   │       └── security.rs       /etc/passwd, /proc/modules, LSM checks
│   ├── mycelium-cli/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs           CLI entry point, clap args
│   │       ├── output.rs         TableDisplay trait, formatting helpers
│   │       └── commands/
│   │           ├── mod.rs
│   │           ├── process.rs
│   │           ├── memory.rs
│   │           ├── network.rs
│   │           ├── storage.rs
│   │           ├── system.rs
│   │           ├── tuning.rs
│   │           ├── service.rs
│   │           ├── log.rs
│   │           ├── security.rs
│   │           └── policy.rs
│   ├── mycelium-mcp/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs           MCP server entry, clap args, stdio transport
│   │       ├── lib.rs            MyceliumMcpService struct, policy/audit helpers
│   │       ├── audit.rs          StderrAuditLog (tracing-based)
│   │       └── tools/
│   │           ├── mod.rs        #[tool_router] with all 32 #[tool] methods
│   │           ├── response.rs   ok_json(), ok_text(), err_text(), dry_run_text()
│   │           ├── process.rs    PidRequest, KillRequest, handlers
│   │           ├── memory.rs     handle_info, handle_process
│   │           ├── network.rs    FirewallAddRequest, FirewallRemoveRequest, handlers
│   │           ├── storage.rs    handle_disks/partitions/mounts/io
│   │           ├── system.rs     handle_info/kernel/cpu/uptime
│   │           ├── tuning.rs     KeyRequest, PrefixRequest, SetRequest, handlers
│   │           ├── service.rs    NameRequest, ActionRequest, handlers
│   │           ├── log.rs        LogReadRequest, handle_read
│   │           └── security.rs   handle_users/groups/modules/status
│   └── mycelium-windows/         Phase 4 (placeholder)
├── examples/
│   └── policy.toml               Example policy config
├── docs/                         Documentation
└── .github/
    └── workflows/
        └── ci.yml                CI pipeline
```
