//! # Aegis Edge Ingestion Agent Daemon
//!
//! Asynchronous userspace runtime consuming from in-kernel eBPF ring buffers,
//! sanitizing telemetry payloads, maintaining local process trees, and streaming
//! to the distributed event pipeline.

#![deny(unsafe_code)]

mod sanitizer;

use aegis_core::HostProcessTree;
use aegis_proto::{AegisEventType, RawKernelEvent, TelemetryEvent, MAX_COMM_LEN, MAX_PATH_LEN};
use sanitizer::sanitize_telemetry_string;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize structured JSON logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "Starting AegisKernel Edge Ingestion Agent"
    );

    let mut process_tree = HostProcessTree::new();

    info!("Initializing BPF ring buffer consumer pipeline");

    // Comprehensive demonstration stream simulating in-kernel BPF ring buffer records
    let sample_events = vec![
        RawKernelEvent {
            timestamp_ns: 1_000_000,
            pid: 1,
            tgid: 1,
            ppid: 0,
            uid: 0,
            gid: 0,
            event_type: AegisEventType::ProcessExec as u32,
            cgroup_id: 1,
            lineage_hash: 0x1001,
            comm: create_comm_buf(b"systemd"),
            filename: create_path_buf(b"/usr/lib/systemd/systemd"),
        },
        RawKernelEvent {
            timestamp_ns: 2_000_000,
            pid: 4096,
            tgid: 4096,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            event_type: AegisEventType::ProcessExec as u32,
            cgroup_id: 10,
            lineage_hash: 0x2002,
            comm: create_comm_buf(b"curl"),
            filename: create_path_buf(b"/usr/bin/curl -u admin:token=SECRET123"),
        },
        RawKernelEvent {
            timestamp_ns: 3_000_000,
            pid: 4096,
            tgid: 4096,
            ppid: 1,
            uid: 0, // Privilege escalation to root
            gid: 0,
            event_type: AegisEventType::PrivilegeEscalation as u32,
            cgroup_id: 10,
            lineage_hash: 0x2002,
            comm: create_comm_buf(b"curl"),
            filename: create_path_buf(b"/usr/bin/curl"),
        },
        RawKernelEvent {
            timestamp_ns: 4_000_000,
            pid: 4096,
            tgid: 4096,
            ppid: 1,
            uid: 0,
            gid: 0,
            event_type: AegisEventType::MemoryProtect as u32, // Fileless code injection
            cgroup_id: 10,
            lineage_hash: 0x2002,
            comm: create_comm_buf(b"curl"),
            filename: create_path_buf(b"mprotect(PROT_EXEC)"),
        },
        RawKernelEvent {
            timestamp_ns: 5_000_000,
            pid: 4096,
            tgid: 4096,
            ppid: 1,
            uid: 0,
            gid: 0,
            event_type: AegisEventType::SocketConnect as u32, // Outbound C2 connection
            cgroup_id: 10,
            lineage_hash: 0x2002,
            comm: create_comm_buf(b"curl"),
            filename: create_path_buf(b"connect(198.51.100.24:4444)"),
        },
        RawKernelEvent {
            timestamp_ns: 6_000_000,
            pid: 4096,
            tgid: 4096,
            ppid: 1,
            uid: 0,
            gid: 0,
            event_type: AegisEventType::GhostShunt as u32, // Trapped in Ghost-Mirror deception
            cgroup_id: 10,
            lineage_hash: 0x2002,
            comm: create_comm_buf(b"curl"),
            filename: create_path_buf(b"ghost_mirror_shunt(active)"),
        },
    ];

    for raw in sample_events {
        match TelemetryEvent::from_raw(&raw) {
            Ok(mut event) => {
                event.filename = sanitize_telemetry_string(&event.filename);

                match event.event_type {
                    AegisEventType::ProcessExec | AegisEventType::ProcessExit => {
                        info!(
                            pid = event.pid,
                            comm = %event.comm,
                            event_type = ?event.event_type,
                            cmd = %event.filename,
                            "Process lifecycle event ingested"
                        );
                    }
                    AegisEventType::PrivilegeEscalation => {
                        warn!(
                            pid = event.pid,
                            uid = event.uid,
                            comm = %event.comm,
                            "PRIVILEGE ESCALATION DETECTED: Process transitioned to UID 0 (root)"
                        );
                    }
                    AegisEventType::MemoryProtect => {
                        error!(
                            pid = event.pid,
                            comm = %event.comm,
                            "FILELESS INJECTION DETECTED: Process allocated executable memory (PROT_EXEC)"
                        );
                    }
                    AegisEventType::SocketConnect => {
                        info!(
                            pid = event.pid,
                            comm = %event.comm,
                            target = %event.filename,
                            "Outbound socket connection tracked"
                        );
                    }
                    AegisEventType::GhostShunt | AegisEventType::CanaryHit => {
                        warn!(
                            pid = event.pid,
                            comm = %event.comm,
                            "GHOST-MIRROR DECEPTION ACTIVE: Malicious process shunted to synthetic memory"
                        );
                    }
                }

                process_tree.ingest_event(&event);

                if let Some(entity) = process_tree.get_process(event.pid) {
                    if entity.blast_radius > 3.0 {
                        warn!(
                            pid = entity.pid,
                            blast_radius = entity.blast_radius,
                            "THREAT BLAST RADIUS EXCEEDED THRESHOLD: Triggering AI Swarm Triage"
                        );
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to parse raw kernel event");
            }
        }
    }

    info!(
        active_processes = process_tree.len(),
        "AegisKernel Edge Ingestion Agent operational and healthy"
    );

    Ok(())
}

fn create_comm_buf(src: &[u8]) -> [u8; MAX_COMM_LEN] {
    let mut buf = [0u8; MAX_COMM_LEN];
    let len = src.len().min(MAX_COMM_LEN);
    buf[..len].copy_from_slice(&src[..len]);
    buf
}

fn create_path_buf(src: &[u8]) -> [u8; MAX_PATH_LEN] {
    let mut buf = [0u8; MAX_PATH_LEN];
    let len = src.len().min(MAX_PATH_LEN);
    buf[..len].copy_from_slice(&src[..len]);
    buf
}
