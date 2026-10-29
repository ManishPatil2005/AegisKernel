//! # Aegis In-Kernel eBPF Probe Loader & Bindings
//!
//! Exposes eBPF program bytecode definitions, map configurations,
//! and ring-buffer attachment helpers.

#![deny(unsafe_code)]
#![warn(missing_docs)]

/// Path to the compiled eBPF object bytecode.
pub const EBPF_OBJECT_PATH: &str = "bpf/aegis_probes.bpf.o";

/// Name of the primary BPF ring buffer map.
pub const RINGBUF_MAP_NAME: &str = "aegis_events_ringbuf";

/// Default capacity for the in-kernel BPF ring buffer (64 MB).
pub const DEFAULT_RINGBUF_SIZE: u32 = 64 * 1024 * 1024;
