/// Storage queries via /proc, /sys/block, and statvfs.

use mycelium_core::error::Result;
use mycelium_core::types::*;
use std::fs;

fn read_block_attr(device: &str, attr: &str) -> Option<String> {
	fs::read_to_string(format!("/sys/block/{device}/{attr}"))
		.ok()
		.map(|s| s.trim().to_string())
		.filter(|s| !s.is_empty())
}

pub fn list_disks() -> Result<Vec<DiskInfo>> {
	let mut disks = Vec::new();

	for entry in fs::read_dir("/sys/block")? {
		let entry = entry?;
		let name = entry.file_name().to_string_lossy().to_string();

		// Skip loopback, ram, dm devices for cleaner output
		if name.starts_with("loop") || name.starts_with("ram") {
			continue;
		}

		let model = read_block_attr(&name, "device/model");
		let serial = read_block_attr(&name, "device/serial");

		let size_sectors: u64 = read_block_attr(&name, "size")
			.and_then(|s| s.parse().ok())
			.unwrap_or(0);

		let removable = read_block_attr(&name, "removable")
			.map(|s| s == "1")
			.unwrap_or(false);

		let rotational = read_block_attr(&name, "queue/rotational")
			.map(|s| s == "1")
			.unwrap_or(false);

		disks.push(DiskInfo {
			name,
			model,
			serial,
			size_bytes: size_sectors * 512,
			removable,
			rotational,
		});
	}

	disks.sort_by(|a, b| a.name.cmp(&b.name));
	Ok(disks)
}

pub fn list_partitions() -> Result<Vec<Partition>> {
	let content = fs::read_to_string("/proc/partitions")?;
	let mut partitions = Vec::new();

	for line in content.lines().skip(2) {
		let fields: Vec<&str> = line.split_whitespace().collect();
		if fields.len() < 4 {
			continue;
		}

		let name = fields[3].to_string();

		// Skip whole disks (no digit suffix) and loopback
		if name.starts_with("loop") || name.starts_with("ram") {
			continue;
		}

		// Determine parent disk
		let parent = name
			.trim_end_matches(|c: char| c.is_ascii_digit())
			.trim_end_matches('p') // nvme0n1p1 -> nvme0n1
			.to_string();

		let blocks: u64 = fields[2].parse().unwrap_or(0);

		// Try to find filesystem info from lsblk-style sysfs attributes
		let fs_type = fs::read_to_string(format!(
			"/sys/class/block/{name}/device/../{name}/../../{name}/dm/uuid"
		))
		.ok()
		.or_else(|| {
			// Check if blkid info available in /run
			None
		});

		// Check mount info for this partition
		let mount_point = find_mount_point(&name);

		partitions.push(Partition {
			name,
			parent_disk: parent,
			size_bytes: blocks * 1024,
			filesystem: fs_type,
			mount_point,
			label: None,
			uuid: None,
		});
	}

	partitions.sort_by(|a, b| a.name.cmp(&b.name));
	Ok(partitions)
}

fn find_mount_point(part_name: &str) -> Option<String> {
	let dev_path = format!("/dev/{part_name}");
	fs::read_to_string("/proc/mounts")
		.ok()
		.and_then(|content| {
			content
				.lines()
				.find(|l| l.starts_with(&dev_path))
				.map(|l| {
					l.split_whitespace()
						.nth(1)
						.unwrap_or("")
						.to_string()
				})
		})
}

pub fn list_mounts() -> Result<Vec<MountPoint>> {
	let content = fs::read_to_string("/proc/mounts")?;
	let mut mounts = Vec::new();

	for line in content.lines() {
		let fields: Vec<&str> = line.split_whitespace().collect();
		if fields.len() < 4 {
			continue;
		}

		let device = fields[0].to_string();
		let mount_path = fields[1].to_string();
		let filesystem = fields[2].to_string();
		let options = fields[3].to_string();

		// Skip pseudo-filesystems for cleaner output
		if matches!(
			filesystem.as_str(),
			"proc" | "sysfs" | "devtmpfs" | "securityfs" | "cgroup"
				| "cgroup2" | "pstore" | "efivarfs" | "bpf"
				| "tracefs" | "debugfs" | "configfs" | "fusectl"
				| "hugetlbfs" | "mqueue" | "autofs" | "rpc_pipefs"
				| "devpts"
		) {
			continue;
		}

		// Get space info via statvfs
		let (total, used, available, use_pct) = statvfs_info(&mount_path);

		mounts.push(MountPoint {
			device,
			mount_path,
			filesystem,
			options,
			total_bytes: total,
			used_bytes: used,
			available_bytes: available,
			use_percent: use_pct,
		});
	}

	Ok(mounts)
}

fn statvfs_info(path: &str) -> (u64, u64, u64, f64) {
	match nix::sys::statvfs::statvfs(path) {
		Ok(stat) => {
			let block_size = stat.block_size() as u64;
			let total = stat.blocks() * block_size;
			let available = stat.blocks_available() * block_size;
			let free = stat.blocks_free() * block_size;
			let used = total.saturating_sub(free);
			let use_pct = if total > 0 {
				(used as f64 / total as f64) * 100.0
			} else {
				0.0
			};
			(total, used, available, use_pct)
		}
		Err(_) => (0, 0, 0, 0.0),
	}
}

pub fn io_stats() -> Result<Vec<IoStats>> {
	let content = fs::read_to_string("/proc/diskstats")?;
	let mut stats = Vec::new();

	for line in content.lines() {
		let fields: Vec<&str> = line.split_whitespace().collect();
		if fields.len() < 14 {
			continue;
		}

		let device = fields[2].to_string();

		// Skip loopback and ram devices
		if device.starts_with("loop") || device.starts_with("ram") {
			continue;
		}

		let parse = |idx: usize| -> u64 { fields[idx].parse().unwrap_or(0) };

		// Sector size is 512 bytes for /proc/diskstats
		stats.push(IoStats {
			device,
			reads_completed: parse(3),
			writes_completed: parse(7),
			read_bytes: parse(5) * 512,  // sectors read * 512
			write_bytes: parse(9) * 512, // sectors written * 512
			io_in_progress: parse(11),
			io_time_ms: parse(12),
		});
	}

	Ok(stats)
}
