//! Mycelium MCP server binary.

use std::sync::Arc;

use clap::Parser;
use rmcp::ServiceExt;
use rmcp::transport::stdio;
use tracing_subscriber::EnvFilter;

use mycelium_core::policy::config::load_policy;
use mycelium_mcp::MyceliumMcpService;
use mycelium_mcp::audit::StderrAuditLog;

#[derive(Parser)]
#[command(name = "mycelium-mcp", about = "Mycelium MCP server")]
struct Args {
	/// Path to policy TOML config file
	#[arg(long)]
	config: Option<String>,

	/// Agent name for policy resolution
	#[arg(long, default_value = "default")]
	agent: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	// Tracing goes to stderr -- stdout is reserved for MCP JSON-RPC
	tracing_subscriber::fmt()
		.with_env_filter(
			EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
		)
		.with_writer(std::io::stderr)
		.init();

	let args = Args::parse();

	let policy = Arc::new(load_policy(args.config.as_deref()));
	let audit = Arc::new(StderrAuditLog);

	#[cfg(target_os = "linux")]
	let linux_platform = Arc::new(mycelium_linux::LinuxPlatform::new());
	#[cfg(target_os = "linux")]
	let platform: Arc<dyn mycelium_core::platform::Platform> = Arc::clone(&linux_platform)
		as Arc<dyn mycelium_core::platform::Platform>;

	#[cfg(target_os = "windows")]
	let platform: Arc<dyn mycelium_core::platform::Platform> =
		Arc::new(mycelium_windows::WindowsPlatform);

	#[cfg(not(any(target_os = "linux", target_os = "windows")))]
	compile_error!("mycelium-mcp: unsupported platform");

	#[cfg(all(target_os = "linux", feature = "ebpf"))]
	let service = {
		let svc = MyceliumMcpService::new(platform, policy, audit, args.agent);
		svc.with_probe_platform(
			linux_platform as Arc<dyn mycelium_core::platform::ProbePlatform>,
		)
	};

	#[cfg(not(all(target_os = "linux", feature = "ebpf")))]
	let service = MyceliumMcpService::new(platform, policy, audit, args.agent);

	tracing::info!("mycelium-mcp starting on stdio");

	let server = service.serve(stdio()).await?;
	server.waiting().await?;

	Ok(())
}
