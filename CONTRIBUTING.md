# Contributing to Mycelium

Thanks for your interest in contributing. This document covers the basics for getting started.

## Getting Started

### Requirements

- Rust 2024 edition (rustc 1.85+)
- Linux or Windows
- For eBPF probes (optional): `bpf-linker`, nightly Rust, kernel 5.8+

### Build and Test

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```

All four commands must pass before submitting a PR.

### eBPF (optional)

```bash
cargo install bpf-linker
cargo build --workspace --features mycelium-linux/ebpf
```

## Code Style

### Formatting

- Tabs for indentation (enforced by `rustfmt.toml`)
- Run `cargo fmt --all` before committing

### Naming

- PascalCase for types, traits, enums
- snake_case for functions, methods, variables
- Constants in UPPER_SNAKE_CASE

### Conventions

- Custom error enum (`MyceliumError`) with manual `Display` + `Error` impls -- no `thiserror`
- `#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]` on core types
- Guard clauses over deep nesting
- Doc comments (`///`) on all public API items
- Unit tests in `#[cfg(test)]` modules, integration tests in `tests/`

## Project Structure

| Crate | Purpose |
|-------|---------|
| `mycelium-core` | Types, `Platform` trait, errors, policy engine (zero deps) |
| `mycelium-linux` | Linux backend (`/proc`, `/sys`, eBPF) |
| `mycelium-windows` | Windows backend (WinAPI, WMI, sysinfo) |
| `mycelium-cli` | CLI binary |
| `mycelium-mcp` | MCP server for AI agents |
| `mycelium-ebpf-common` | Shared eBPF event types (`#![no_std]`) |
| `mycelium-ebpf` | eBPF programs (separate build target) |

## Adding a New Platform Method

1. Add the method signature to the `Platform` trait in `mycelium-core/src/platform.rs` with a default `Unsupported` return
2. Implement it in `mycelium-linux` and/or `mycelium-windows`
3. Add a CLI subcommand in `mycelium-cli`
4. Register an MCP tool in `mycelium-mcp`
5. Add unit tests for any parsing logic
6. Update docs: `platform-api.md`, `types.md`, `cli.md`, `mcp-server.md`

## Pull Requests

- Keep PRs focused -- one feature or fix per PR
- Include tests for new functionality
- Update documentation if adding/changing public API
- All CI checks must pass (build, test, clippy, fmt)
- Write a clear description of what changed and why

## Reporting Issues

Open an issue on GitHub with:

- What you expected vs what happened
- Steps to reproduce
- OS and Rust version
- Relevant logs or error output

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
