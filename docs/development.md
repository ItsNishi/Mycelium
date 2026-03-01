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
- **Policy engine tests:** 12 tests in `mycelium-core/src/policy/mod.rs` covering roles, specificity, filters, dry-run, and overrides

### What's Tested

| Area | Tests | Coverage |
|------|-------|----------|
| Default policy (allow all) | 1 | Default behavior |
| ReadOnly role | 1 | Allows reads, denies all 6 write capabilities |
| Operator role | 1 | Allows reads + process/service, denies 4 capabilities |
| Admin role | 1 | Allows everything |
| Profile overrides | 1 | Tool-level allow overrides capability-level deny |
| Service name filter | 1 | Filter matches/mismatches on service names |
| Tunable prefix filter | 1 | Filter matches/mismatches on sysctl prefixes |
| Dry-run propagation | 1 | Profile dry-run flag |
| Global dry-run override | 1 | Global flag overrides profile |
| Unknown profile fallback | 1 | Falls back to default profile |
| Last rule wins | 1 | Same specificity, order determines winner |
| Specificity ordering | 1 | More specific target always wins |

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

This keeps `mycelium-core` dependency-free by default. The CLI enables serde:

```toml
mycelium-core = { path = "../mycelium-core", features = ["serde"] }
```

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

6. **Add tests** in the implementing crate.

7. **If it's a write operation**, add it to the appropriate `Capability` in `capability.rs` and update role presets if needed.

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
│   ├── mycelium-mcp/             Phase 2 (placeholder)
│   └── mycelium-windows/         Phase 4 (placeholder)
├── examples/
│   └── policy.toml               Example policy config
├── docs/                         Documentation
└── .github/
    └── workflows/
        └── ci.yml                CI pipeline
```
