//! Mycelium Windows backend -- implements Platform using sysinfo, WinAPI, and WMI.

#![cfg(target_os = "windows")]

mod memory;
mod network;
mod platform;
mod process;
mod security;
mod service;
mod storage;
mod system;
mod tuning;

pub use platform::WindowsPlatform;
