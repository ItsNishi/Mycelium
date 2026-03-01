//! Storage information via sysinfo and WMI.

use sysinfo::Disks;
use wmi::{COMLibrary, WMIConnection};

use mycelium_core::error::{MyceliumError, Result};
use mycelium_core::types::{DiskInfo, IoStats, MountPoint, Partition};

pub fn list_disks() -> Result<Vec<DiskInfo>> {
	let disks = Disks::new_with_refreshed_list();

	let mut seen = std::collections::HashSet::new();
	let mut result = Vec::new();

	for disk in disks.list() {
		let name = disk.name().to_string_lossy().to_string();
		if !seen.insert(name.clone()) {
			continue;
		}

		result.push(DiskInfo {
			name,
			model: None,
			serial: None,
			size_bytes: disk.total_space(),
			removable: disk.is_removable(),
			rotational: !matches!(disk.kind(), sysinfo::DiskKind::Ssd),
		});
	}

	Ok(result)
}

#[derive(serde::Deserialize)]
#[allow(non_snake_case)]
struct WmiPartition {
	Name: Option<String>,
	DiskIndex: Option<u32>,
	Size: Option<u64>,
	Type: Option<String>,
}

pub fn list_partitions() -> Result<Vec<Partition>> {
	let com = COMLibrary::new().map_err(|e| MyceliumError::OsError {
		code: -1,
		message: format!("COM init failed: {e}"),
	})?;

	let wmi = WMIConnection::new(com).map_err(|e| MyceliumError::OsError {
		code: -1,
		message: format!("WMI connection failed: {e}"),
	})?;

	let results: Vec<WmiPartition> = wmi
		.raw_query("SELECT Name, DiskIndex, Size, Type FROM Win32_DiskPartition")
		.map_err(|e| MyceliumError::OsError {
			code: -1,
			message: format!("WMI partition query failed: {e}"),
		})?;

	let partitions = results
		.into_iter()
		.map(|p| Partition {
			name: p.Name.unwrap_or_default(),
			parent_disk: format!("disk{}", p.DiskIndex.unwrap_or(0)),
			size_bytes: p.Size.unwrap_or(0),
			filesystem: None,
			mount_point: None,
			label: None,
			uuid: None,
		})
		.collect();

	Ok(partitions)
}

pub fn list_mounts() -> Result<Vec<MountPoint>> {
	let disks = Disks::new_with_refreshed_list();

	let mounts = disks
		.list()
		.iter()
		.map(|disk| {
			let total = disk.total_space();
			let available = disk.available_space();
			let used = total.saturating_sub(available);
			let use_percent = if total > 0 {
				(used as f64 / total as f64) * 100.0
			} else {
				0.0
			};

			MountPoint {
				device: disk.name().to_string_lossy().to_string(),
				mount_path: disk.mount_point().to_string_lossy().to_string(),
				filesystem: String::from_utf8_lossy(disk.file_system()).to_string(),
				options: String::new(),
				total_bytes: total,
				used_bytes: used,
				available_bytes: available,
				use_percent,
			}
		})
		.collect();

	Ok(mounts)
}

#[derive(serde::Deserialize)]
#[allow(non_snake_case)]
struct WmiDiskPerf {
	Name: Option<String>,
	DiskReadsPerSec: Option<u64>,
	DiskWritesPerSec: Option<u64>,
	DiskReadBytesPerSec: Option<u64>,
	DiskWriteBytesPerSec: Option<u64>,
	CurrentDiskQueueLength: Option<u64>,
	PercentDiskTime: Option<u64>,
}

pub fn io_stats() -> Result<Vec<IoStats>> {
	let com = COMLibrary::new().map_err(|e| MyceliumError::OsError {
		code: -1,
		message: format!("COM init failed: {e}"),
	})?;

	let wmi = WMIConnection::new(com).map_err(|e| MyceliumError::OsError {
		code: -1,
		message: format!("WMI connection failed: {e}"),
	})?;

	let results: Vec<WmiDiskPerf> = wmi
		.raw_query(
			"SELECT Name, DiskReadsPerSec, DiskWritesPerSec, \
			 DiskReadBytesPerSec, DiskWriteBytesPerSec, \
			 CurrentDiskQueueLength, PercentDiskTime \
			 FROM Win32_PerfFormattedData_PerfDisk_PhysicalDisk",
		)
		.map_err(|e| MyceliumError::OsError {
			code: -1,
			message: format!("WMI disk perf query failed: {e}"),
		})?;

	let stats = results
		.into_iter()
		.filter(|r| {
			// Skip the "_Total" aggregate
			r.Name.as_deref() != Some("_Total")
		})
		.map(|r| IoStats {
			device: r.Name.unwrap_or_default(),
			reads_completed: r.DiskReadsPerSec.unwrap_or(0),
			writes_completed: r.DiskWritesPerSec.unwrap_or(0),
			read_bytes: r.DiskReadBytesPerSec.unwrap_or(0),
			write_bytes: r.DiskWriteBytesPerSec.unwrap_or(0),
			io_in_progress: r.CurrentDiskQueueLength.unwrap_or(0),
			io_time_ms: r.PercentDiskTime.unwrap_or(0),
		})
		.collect();

	Ok(stats)
}
