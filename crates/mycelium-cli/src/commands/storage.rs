use clap::Subcommand;
use mycelium_core::platform::Platform;
use mycelium_core::types::*;

use crate::output::*;

#[derive(Subcommand)]
pub enum StorageCmd {
	/// List physical disks
	Disks,
	/// List partitions
	Partitions,
	/// List mounted filesystems
	Mounts,
	/// Show I/O statistics
	Io,
}

impl StorageCmd {
	pub fn run(&self, platform: &dyn Platform, format: OutputFormat) {
		match self {
			Self::Disks => match platform.list_disks() {
				Ok(disks) => print_list(&disks, format),
				Err(e) => eprintln!("error: {e}"),
			},
			Self::Partitions => match platform.list_partitions() {
				Ok(parts) => print_list(&parts, format),
				Err(e) => eprintln!("error: {e}"),
			},
			Self::Mounts => match platform.list_mounts() {
				Ok(mounts) => print_list(&mounts, format),
				Err(e) => eprintln!("error: {e}"),
			},
			Self::Io => match platform.io_stats() {
				Ok(stats) => print_list(&stats, format),
				Err(e) => eprintln!("error: {e}"),
			},
		}
	}
}

impl TableDisplay for DiskInfo {
	fn print_header() {
		println!(
			"{:<12} {:<30} {:>12} {:<5} {:<4}",
			"NAME", "MODEL", "SIZE", "REMOV", "ROT"
		);
	}

	fn print_row(&self) {
		println!(
			"{:<12} {:<30} {:>12} {:<5} {:<4}",
			self.name,
			self.model.as_deref().unwrap_or("-"),
			human_bytes(self.size_bytes),
			if self.removable { "yes" } else { "no" },
			if self.rotational { "yes" } else { "no" },
		);
	}
}

impl TableDisplay for Partition {
	fn print_header() {
		println!(
			"{:<15} {:<12} {:>12} {:<10} MOUNT",
			"NAME", "DISK", "SIZE", "FS"
		);
	}

	fn print_row(&self) {
		println!(
			"{:<15} {:<12} {:>12} {:<10} {}",
			self.name,
			self.parent_disk,
			human_bytes(self.size_bytes),
			self.filesystem.as_deref().unwrap_or("-"),
			self.mount_point.as_deref().unwrap_or("-"),
		);
	}
}

impl TableDisplay for MountPoint {
	fn print_header() {
		println!(
			"{:<25} {:<20} {:<8} {:>12} {:>12} {:>6}",
			"DEVICE", "MOUNT", "FS", "TOTAL", "USED", "USE%"
		);
	}

	fn print_row(&self) {
		println!(
			"{:<25} {:<20} {:<8} {:>12} {:>12} {:>5.1}%",
			truncate(&self.device, 25),
			truncate(&self.mount_path, 20),
			self.filesystem,
			human_bytes(self.total_bytes),
			human_bytes(self.used_bytes),
			self.use_percent,
		);
	}
}

impl TableDisplay for IoStats {
	fn print_header() {
		println!(
			"{:<12} {:>10} {:>10} {:>12} {:>12} {:>6} {:>10}",
			"DEVICE", "READS", "WRITES", "READ", "WRITTEN", "IO", "TIME_MS"
		);
	}

	fn print_row(&self) {
		println!(
			"{:<12} {:>10} {:>10} {:>12} {:>12} {:>6} {:>10}",
			self.device,
			self.reads_completed,
			self.writes_completed,
			human_bytes(self.read_bytes),
			human_bytes(self.write_bytes),
			self.io_in_progress,
			self.io_time_ms,
		);
	}
}
