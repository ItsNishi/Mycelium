//! Mycelium Windows backend -- implements Platform using sysinfo, WinAPI, and WMI.

#![cfg(target_os = "windows")]

mod handle;
mod hooks;
mod memory;
mod network;
mod pe;
mod persistence;
mod platform;
mod privilege;
mod process;
mod security;
mod service;
mod storage;
mod system;
mod tuning;

pub use platform::WindowsPlatform;
