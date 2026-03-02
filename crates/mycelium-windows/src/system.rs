//! System information via sysinfo, registry, and WMI.

use sysinfo::System;
use wmi::{COMLibrary, WMIConnection};
use winreg::enums::HKEY_LOCAL_MACHINE;
use winreg::RegKey;

use mycelium_core::error::{MyceliumError, Result};
use mycelium_core::types::{CpuInfo, KernelInfo, SystemInfo};

#[derive(serde::Deserialize)]
#[allow(non_snake_case)]
struct WmiProcessor {
	L2CacheSize: Option<u32>,
	L3CacheSize: Option<u32>,
	CurrentClockSpeed: Option<u32>,
}

struct CpuWmiInfo {
	cache_size_kb: u64,
	current_clock_mhz: Option<f64>,
}

fn get_cpu_wmi_info() -> CpuWmiInfo {
	let com = match COMLibrary::new() {
		Ok(c) => c,
		Err(_) => return CpuWmiInfo { cache_size_kb: 0, current_clock_mhz: None },
	};
	let wmi = match WMIConnection::new(com) {
		Ok(w) => w,
		Err(_) => return CpuWmiInfo { cache_size_kb: 0, current_clock_mhz: None },
	};
	let results: Vec<WmiProcessor> = wmi
		.raw_query("SELECT L2CacheSize, L3CacheSize, CurrentClockSpeed FROM Win32_Processor")
		.unwrap_or_default();

	results
		.first()
		.map(|p| CpuWmiInfo {
			cache_size_kb: p.L2CacheSize.unwrap_or(0) as u64 + p.L3CacheSize.unwrap_or(0) as u64,
			current_clock_mhz: p.CurrentClockSpeed.map(|v| v as f64),
		})
		.unwrap_or(CpuWmiInfo { cache_size_kb: 0, current_clock_mhz: None })
}

pub fn system_info() -> Result<SystemInfo> {
	let boot_time = System::boot_time();
	let uptime_secs = System::uptime();

	Ok(SystemInfo {
		hostname: System::host_name().unwrap_or_default(),
		os_name: System::name().unwrap_or_else(|| "Windows".to_string()),
		os_version: System::os_version().unwrap_or_default(),
		architecture: std::env::consts::ARCH.to_string(),
		uptime_seconds: uptime_secs,
		boot_time,
	})
}

pub fn kernel_info() -> Result<KernelInfo> {
	let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
	let nt_key = hklm
		.open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
		.map_err(|e| MyceliumError::OsError {
			code: e.raw_os_error().unwrap_or(-1),
			message: format!("cannot open NT\\CurrentVersion: {e}"),
		})?;

	let build: String = nt_key
		.get_value("CurrentBuildNumber")
		.unwrap_or_default();
	let product: String = nt_key
		.get_value("ProductName")
		.unwrap_or_default();
	let display_version: String = nt_key
		.get_value("DisplayVersion")
		.unwrap_or_default();
	let ubr: u32 = nt_key.get_value("UBR").unwrap_or(0);

	let kernel_version = System::kernel_version().unwrap_or_default();

	Ok(KernelInfo {
		version: format!("{product} {display_version}"),
		release: format!("{kernel_version}.{build}.{ubr}"),
		architecture: std::env::consts::ARCH.to_string(),
		command_line: String::new(), // no kernel command line on Windows
	})
}

pub fn cpu_info() -> Result<CpuInfo> {
	let mut sys = System::new();
	sys.refresh_cpu_all();

	let cpus = sys.cpus();
	let model = cpus
		.first()
		.map(|c| c.brand().to_string())
		.unwrap_or_default();
	let sysinfo_freq = cpus
		.first()
		.map(|c| c.frequency() as f64)
		.unwrap_or(0.0);

	let usage: f64 = if cpus.is_empty() {
		0.0
	} else {
		cpus.iter().map(|c| c.cpu_usage() as f64).sum::<f64>() / cpus.len() as f64
	};

	let wmi_info = get_cpu_wmi_info();
	let freq = wmi_info.current_clock_mhz.unwrap_or(sysinfo_freq);

	Ok(CpuInfo {
		model_name: model,
		cores_physical: System::physical_core_count().unwrap_or(0) as u32,
		cores_logical: cpus.len() as u32,
		frequency_mhz: freq,
		cache_size_kb: wmi_info.cache_size_kb,
		load_average: [0.0, 0.0, 0.0], // no load average on Windows
		usage_percent: usage,
	})
}

pub fn uptime() -> Result<u64> {
	Ok(System::uptime())
}
