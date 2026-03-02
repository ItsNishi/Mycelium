#[cfg(feature = "ebpf")]
fn main() {
	let ebpf_crate = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../mycelium-ebpf");

	aya_build::build_ebpf(
		[aya_build::Package {
			name: "mycelium-ebpf",
			root_dir: ebpf_crate
				.to_str()
				.expect("ebpf crate path is not valid UTF-8"),
			..Default::default()
		}],
		aya_build::Toolchain::Nightly,
	)
	.expect("failed to build eBPF programs");
}

#[cfg(not(feature = "ebpf"))]
fn main() {}
