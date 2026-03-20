mod commands;
mod output;

use clap::{Parser, Subcommand};
use output::OutputFormat;

#[derive(Parser)]
#[command(
	name = "mycelium",
	version,
	about = "Structured OS introspection for humans and AI agents"
)]
struct Cli {
	/// Output as JSON
	#[arg(long, global = true)]
	json: bool,

	/// Dry-run mode (no write operations)
	#[arg(long, global = true)]
	dry_run: bool,

	/// Path to policy config file
	#[arg(long, global = true)]
	config: Option<String>,

	#[command(subcommand)]
	command: Command,
}

#[derive(Subcommand)]
enum Command {
	/// Process management
	#[command(subcommand)]
	Process(commands::process::ProcessCmd),

	/// Memory information
	#[command(subcommand)]
	Memory(commands::memory::MemoryCmd),

	/// Network information
	#[command(subcommand)]
	Network(commands::network::NetworkCmd),

	/// Storage information
	#[command(subcommand)]
	Storage(commands::storage::StorageCmd),

	/// System information
	#[command(subcommand)]
	System(commands::system::SystemCmd),

	/// Kernel tunables (sysctl)
	#[command(subcommand)]
	Tuning(commands::tuning::TuningCmd),

	/// Service management
	#[command(subcommand)]
	Service(commands::service::ServiceCmd),

	/// Log queries
	Log(commands::log::LogCmd),

	/// Security information
	#[command(subcommand)]
	Security(commands::security::SecurityCmd),

	/// Policy management
	#[command(subcommand)]
	Policy(commands::policy::PolicyCmd),

	/// eBPF probe management (requires root/CAP_BPF)
	#[command(subcommand)]
	Probe(commands::probe::ProbeCmd),
}

fn main() {
	let cli = Cli::parse();

	let format = if cli.json {
		OutputFormat::Json
	} else {
		OutputFormat::Table
	};

	#[cfg(target_os = "linux")]
	let platform = mycelium_linux::LinuxPlatform::new();

	#[cfg(target_os = "windows")]
	let platform = mycelium_windows::WindowsPlatform::new();

	#[cfg(not(any(target_os = "linux", target_os = "windows")))]
	{
		eprintln!("error: this platform is not yet supported");
		std::process::exit(1);
	}

	let dry_run = cli.dry_run;

	match cli.command {
		Command::Process(cmd) => cmd.run(&platform, format, dry_run),
		Command::Memory(cmd) => cmd.run(&platform, format, dry_run),
		Command::Network(cmd) => cmd.run(&platform, format, dry_run),
		Command::Storage(cmd) => cmd.run(&platform, format),
		Command::System(cmd) => cmd.run(&platform, format),
		Command::Tuning(cmd) => cmd.run(&platform, format, dry_run),
		Command::Service(cmd) => cmd.run(&platform, format, dry_run),
		Command::Log(cmd) => cmd.run(&platform, format),
		Command::Security(cmd) => cmd.run(&platform, format),
		Command::Policy(cmd) => cmd.run(format),
		Command::Probe(cmd) => {
			#[cfg(all(target_os = "linux", feature = "ebpf"))]
			{
				use mycelium_core::platform::ProbePlatform;
				cmd.run(&platform as &dyn ProbePlatform, format, dry_run);
			}
			#[cfg(not(all(target_os = "linux", feature = "ebpf")))]
			{
				let _ = (cmd, format, dry_run);
				eprintln!("error: probes not available (ebpf feature not enabled)");
				std::process::exit(1);
			}
		}
	}
}
