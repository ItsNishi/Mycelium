//! Mycelium Linux backend -- implements Platform using /proc, /sys, and nix.

mod elf;
mod hooks;
mod memory;
mod network;
mod persistence;
mod platform;
#[cfg(feature = "ebpf")]
pub mod probe;
mod process;
mod security;
mod service;
mod storage;
mod system;
mod tuning;

pub use platform::LinuxPlatform;
