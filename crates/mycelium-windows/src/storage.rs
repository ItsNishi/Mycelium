//! Storage information via sysinfo and WMI.

use std::collections::HashMap;

use sysinfo::Disks;
use wmi::{COMLibrary, WMIConnection};

use mycelium_core::error::{MyceliumError, Result};
use mycelium_core::types::{DiskInfo, IoStats, MountPoint, Partition};

#[derive(serde::Deserialize)]
#[allow(non_snake_case)]
struct WmiDiskDrive {
	DeviceID: Option<String>,
	Model: Option<String>,
	SerialNumber: Option<String>,
}

#[derive(serde::Deserialize)]
#[allow(non_snake_case)]
struct WmiDiskToPartition {
	Antecedent: Option<String>,
	Dependent: Option<String>,
}

#[derive(serde::Deserialize)]
#[allow(non_snake_case)]
struct WmiLogicalToPartition {
	Antecedent: Option<String>,
	Dependent: Option<String>,
}

/// Extract a key value from a WMI association reference string.
///
/// Example input: `"\\\\DESKTOP\\root\\cimv2:Win32_DiskDrive.DeviceID=\"\\\\\\\\.\\\\PHYSICALDRIVE0\""`
/// With key `"DeviceID"` returns `"\\\\.\\PHYSICALDRIVE0"`.
fn extract_wmi_key(reference: &str, key: &str) -> Option<String> {
	let pattern = format!("{key}=\"");
	let start = reference.find(&pattern)? + pattern.len();
	let rest = &reference[start..];
	let end = rest.find('"')?;
	Some(rest[..end].replace("\\\\", "\\"))
}

/// Query WMI to build a map from drive letter (e.g. `"C:"`) to `(model, serial)`.
fn get_disk_drive_info() -> HashMap<String, (Option<String>, Option<String>)> {
	let mut map = HashMap::new();

	let com = match COMLibrary::new() {
		Ok(c) => c,
		Err(_) => return map,
	};
	let wmi = match WMIConnection::new(com) {
		Ok(w) => w,
		Err(_) => return map,
	};

	// 1. Get physical drives
	let drives: Vec<WmiDiskDrive> = wmi
		.raw_query("SELECT DeviceID, Model, SerialNumber FROM Win32_DiskDrive")
		.unwrap_or_default();

	let mut drive_info: HashMap<String, (Option<String>, Option<String>)> = HashMap::new();
	for d in &drives {
		if let Some(ref id) = d.DeviceID {
			drive_info.insert(
				id.clone(),
				(
					d.Model.clone(),
					d.SerialNumber.as_ref().map(|s| s.trim().to_string()),
				),
			);
		}
	}

	// 2. Map physical drive → partition
	let d2p: Vec<WmiDiskToPartition> = wmi
		.raw_query("SELECT Antecedent, Dependent FROM Win32_DiskDriveToDiskPartition")
		.unwrap_or_default();

	// partition name → physical drive DeviceID
	let mut partition_to_drive: HashMap<String, String> = HashMap::new();
	for assoc in &d2p {
		if let (Some(ante), Some(dep)) = (&assoc.Antecedent, &assoc.Dependent)
			&& let Some(drive_id) = extract_wmi_key(ante, "DeviceID")
			&& let Some(part_id) = extract_wmi_key(dep, "DeviceID")
		{
			partition_to_drive.insert(part_id, drive_id);
		}
	}

	// 3. Map partition → logical disk (drive letter)
	let l2p: Vec<WmiLogicalToPartition> = wmi
		.raw_query("SELECT Antecedent, Dependent FROM Win32_LogicalDiskToPartition")
		.unwrap_or_default();

	for assoc in &l2p {
		if let (Some(ante), Some(dep)) = (&assoc.Antecedent, &assoc.Dependent)
			&& let Some(part_id) = extract_wmi_key(ante, "DeviceID")
			&& let Some(letter) = extract_wmi_key(dep, "DeviceID")
			&& let Some(drive_id) = partition_to_drive.get(&part_id)
			&& let Some(info) = drive_info.get(drive_id)
		{
			map.insert(letter, info.clone());
		}
	}

	map
}

pub fn list_disks() -> Result<Vec<DiskInfo>> {
	let disks = Disks::new_with_refreshed_list();
	let drive_info = get_disk_drive_info();

	let mut seen = std::collections::HashSet::new();
	let mut result = Vec::new();

	for disk in disks.list() {
		let name = disk.name().to_string_lossy().to_string();
		if !seen.insert(name.clone()) {
			continue;
		}

		// Look up model/serial by mount point (e.g. "C:\\" → "C:")
		let mount = disk.mount_point().to_string_lossy();
		let mount_key = mount.trim_end_matches('\\').to_string();
		let (model, serial) = drive_info.get(&mount_key).cloned().unwrap_or((None, None));

		result.push(DiskInfo {
			name,
			model,
			serial,
			size_bytes: disk.total_space(),
			removable: disk.is_removable(),
			rotational: !matches!(disk.kind(), sysinfo::DiskKind::SSD),
		});
	}

	Ok(result)
}

#[derive(serde::Deserialize)]
#[allow(non_snake_case, dead_code)]
struct WmiPartition {
	Name: Option<String>,
	DiskIndex: Option<u32>,
	Size: Option<u64>,
	Type: Option<String>,
}

/// (mount_point, filesystem, label, uuid)
type LogicalDiskInfo = (String, Option<String>, Option<String>, Option<String>);

#[derive(serde::Deserialize)]
#[allow(non_snake_case)]
struct WmiLogicalDisk {
	DeviceID: Option<String>,
	FileSystem: Option<String>,
	VolumeName: Option<String>,
	VolumeSerialNumber: Option<String>,
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

	// Query logical disks for filesystem, label, serial
	let logical_disks: Vec<WmiLogicalDisk> = wmi
		.raw_query(
			"SELECT DeviceID, FileSystem, VolumeName, VolumeSerialNumber FROM Win32_LogicalDisk",
		)
		.unwrap_or_default();

	let mut logical_map: HashMap<String, LogicalDiskInfo> = HashMap::new();
	for ld in &logical_disks {
		if let Some(ref dev) = ld.DeviceID {
			logical_map.insert(
				dev.clone(),
				(
					format!("{}\\", dev),
					ld.FileSystem.clone(),
					ld.VolumeName.clone().filter(|s| !s.is_empty()),
					ld.VolumeSerialNumber.clone().filter(|s| !s.is_empty()),
				),
			);
		}
	}

	// Map partition name → logical disk info via association
	let l2p: Vec<WmiLogicalToPartition> = wmi
		.raw_query("SELECT Antecedent, Dependent FROM Win32_LogicalDiskToPartition")
		.unwrap_or_default();

	let mut part_info: HashMap<String, LogicalDiskInfo> = HashMap::new();
	for assoc in &l2p {
		if let (Some(ante), Some(dep)) = (&assoc.Antecedent, &assoc.Dependent)
			&& let Some(part_id) = extract_wmi_key(ante, "DeviceID")
			&& let Some(letter) = extract_wmi_key(dep, "DeviceID")
			&& let Some(info) = logical_map.get(&letter)
		{
			part_info.insert(part_id, info.clone());
		}
	}

	let partitions = results
		.into_iter()
		.map(|p| {
			let name = p.Name.unwrap_or_default();
			let (mount_point, filesystem, label, uuid) = part_info
				.get(&name)
				.cloned()
				.map(|(mp, fs, lbl, ser)| (Some(mp), fs, lbl, ser))
				.unwrap_or((None, None, None, None));

			Partition {
				name,
				parent_disk: format!("disk{}", p.DiskIndex.unwrap_or(0)),
				size_bytes: p.Size.unwrap_or(0),
				filesystem,
				mount_point,
				label,
				uuid,
			}
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
				filesystem: disk.file_system().to_string_lossy().to_string(),
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

#[cfg(test)]
mod tests {
	use super::*;

	// -- extract_wmi_key --

	#[test]
	fn test_extract_wmi_key_device_id() {
		let reference = r#"\\DESKTOP\root\cimv2:Win32_DiskDrive.DeviceID="\\\\.\\PHYSICALDRIVE0""#;
		assert_eq!(
			extract_wmi_key(reference, "DeviceID"),
			Some("\\\\.\\PHYSICALDRIVE0".to_string())
		);
	}

	#[test]
	fn test_extract_wmi_key_drive_letter() {
		let reference = r#"\\DESKTOP\root\cimv2:Win32_LogicalDisk.DeviceID="C:""#;
		assert_eq!(
			extract_wmi_key(reference, "DeviceID"),
			Some("C:".to_string())
		);
	}

	#[test]
	fn test_extract_wmi_key_not_found() {
		let reference = r#"\\DESKTOP\root\cimv2:Win32_DiskDrive.Name="Disk""#;
		assert_eq!(extract_wmi_key(reference, "DeviceID"), None);
	}

	#[test]
	fn test_extract_wmi_key_no_closing_quote() {
		let reference = r#"DeviceID="unterminated"#;
		assert_eq!(extract_wmi_key(reference, "DeviceID"), None);
	}

	#[test]
	fn test_extract_wmi_key_escaped_backslashes() {
		// WMI uses \\\\ for backslashes; extract_wmi_key replaces them
		let reference = r#"DeviceID="C:\\Windows\\System32""#;
		let result = extract_wmi_key(reference, "DeviceID");
		assert_eq!(result, Some(r"C:\Windows\System32".to_string()));
	}

	#[test]
	fn test_extract_wmi_key_empty_value() {
		let reference = r#"DeviceID="""#;
		assert_eq!(extract_wmi_key(reference, "DeviceID"), Some(String::new()));
	}
}
