# Mycelium TODO

Planned development phases for security and reverse engineering features.

## Phase 7: Reverse Engineering & Debugging Primitives

Core infrastructure that later phases depend on.

- [x] **Wildcard pattern search** -- support `??` mask bytes in hex patterns (e.g. `48 8B ?? ?? 89 05`) for signature-style scanning across process memory
- [x] **ELF parser** -- parity with PE inspector: headers, sections, imports/exports, symbols, dynamic linking info. Uses `goblin` crate
- [ ] **Memory protection changes** -- implement `mprotect` (Linux) and `VirtualProtectEx` (Windows) wrappers so code regions can be made writable for patching
- [ ] **Disassembly** -- instruction decoding for memory regions via `iced-x86` or `capstone-rs`, support x86/x86_64/ARM64
- [ ] **Symbol resolution** -- map addresses to function names using debug info (DWARF on Linux, PDB on Windows) and export tables
- [ ] **File I/O eBPF probe** -- trace openat/read/write/close syscalls per process, complements existing syscall and network probes
- [ ] **Memory allocation/deallocation** -- `mmap`/`VirtualAlloc` wrappers for injecting new memory regions into target processes
- [ ] **Stack unwinding** -- generate call stacks from thread context using frame pointers or DWARF CFI
- [ ] **Register reading** -- `ptrace(GETREGS)` on Linux, `GetThreadContext` on Windows for inspecting CPU state per thread
- [ ] MCP tools: `memory_search` wildcard mode, `process_elf_inspect`, `memory_protect`, `memory_disassemble`, `process_symbols`, new eBPF probe types, `process_stack`, `process_registers`

## Phase 8: Advanced Threat Detection

- [ ] **Rootkit detection (Linux)** -- kernel module signature verification, hidden process detection (/proc PID gaps vs task list), hidden port detection (/proc/net vs live sockets), /proc anomaly scanning
- [ ] **Code injection detection (Windows)** -- thread callstack analysis for injected DLLs, RWX memory region scanning, code cave detection (entropy analysis of PE section slack space), PEB/TEB manipulation detection
- [ ] **Anti-debugging detection (cross-platform)** -- Linux: ptrace status, TracerPid, timing checks. Windows: NtGlobalFlag, heap flags, debug object handles
- [ ] **Expanded eBPF probes** -- file access tracing (openat), process execution tracing (sched_process_exec), privilege escalation detection (setuid/setgid/capset syscalls)
- [ ] MCP tools: `security_rootkit_scan`, `security_injection_scan`, `security_antidebug_check`, new eBPF probe types

- [ ] **YARA rule engine** -- integrate yara-x (Rust-native YARA by VirusTotal) for file and process memory scanning, ship default ruleset for common malware indicators
- [ ] **Entropy analysis** -- per-section entropy calculation for PE/ELF binaries to detect packing/encryption
- [ ] **String extraction** -- ASCII/UTF-8/UTF-16 string dumping from binaries and process memory with configurable min length
- [ ] **IOC matching** -- hash-based (MD5/SHA256) file scanning against user-provided IOC lists, suspicious filename pattern matching
- [ ] **Behavioral heuristics** -- process tree anomaly detection (unusual parent-child like Word spawning cmd.exe), PATH hijacking detection, suspicious command-line patterns
- [ ] MCP tools: `scan_yara`, `scan_entropy`, `scan_strings`, `scan_ioc`, `scan_heuristics`

- [ ] **Packet capture** -- lightweight pcap via AF_PACKET (Linux) / Npcap (Windows), BPF filter support, configurable capture limits
- [ ] **DNS query logging** -- passive DNS monitoring via eBPF or packet inspection
- [ ] **TLS fingerprinting** -- JA3/JA4 hash extraction from TLS ClientHello
- [ ] **Network anomaly detection** -- beaconing detection, data exfiltration heuristics, C2 pattern recognition (DNS tunneling, long subdomains)
- [ ] **Connection attribution** -- map network connections to full process trees with command-line context
- [ ] MCP tools: `network_capture`, `network_dns_log`, `network_tls_fingerprint`, `network_anomalies`

- [ ] **Event timeline** -- unified chronological view across process creation, network connections, file access, persistence changes, probe events
- [ ] **Snapshot diffing** -- capture system state at a point in time, diff against later snapshot to identify changes
- [ ] **Report generation** -- structured JSON/TOML export of findings from any scan
- [ ] **Evidence collection** -- bundle artifacts (memory dumps, process info, network captures, scan results) into timestamped archive
- [ ] MCP tools: `forensic_timeline`, `forensic_snapshot`, `forensic_diff`, `forensic_report`, `forensic_collect`
