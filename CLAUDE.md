# Mycelium -- CLAUDE.md

## Overview

Mycelium is a Rust library + CLI + MCP server providing structured, typed, cross-platform access to kernel-level OS information. AI agents connect via MCP and get clean JSON responses.

## Build

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace
```

## Architecture

Cargo workspace with shared zero-dep core + platform backends:

- **mycelium-core**: Types, traits, errors, policy engine. Zero deps by default; optional `serde` and `toml` features.
- **mycelium-linux**: Linux backend using /proc, /sys, nix.
- **mycelium-mcp**: MCP server -- 35 tools via rmcp 0.17, stdio transport, policy enforcement, audit logging.
- **mycelium-cli**: CLI binary with clap.
- **mycelium-windows**: Windows backend using WMI, winreg (Phase 4).

## Conventions

- Edition 2024, MIT license
- Tabs for indentation, same-line braces (Rust convention)
- PascalCase for types/traits/enums, snake_case for functions/methods
- Custom error enum with manual Display + Error impls
- `#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]` on core types
- Unit tests in `#[cfg(test)]` modules, integration tests in `tests/`
- Doc comments (`///`) for public API
