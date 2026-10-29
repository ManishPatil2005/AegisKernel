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
use tracing::{info, warn};
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

    // Demonstration synthetic telemetry stream simulating kernel ring buffer consumption
    info!("Initializing BPF ring buffer consumer pipeline");

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
            uid: 0, // Privilege escalation
            gid: 0,
            event_type: AegisEventType::PrivilegeEscalation as u32,
            cgroup_id: 10,
            lineage_hash: 0x2002,
            comm: create_comm_buf(b"curl"),
            filename: create_path_buf(b"/usr/bin/curl"),
        },
    ];

    for raw in sample_events {
        match TelemetryEvent::from_raw(&raw) {
            Ok(mut event) => {
                // Apply security credential sanitization
                event.filename = sanitize_telemetry_string(&event.filename);

                info!(
                    pid = event.pid,
                    ppid = event.ppid,
                    comm = %event.comm,
                    event_type = ?event.event_type,
                    sanitized_cmd = %event.filename,
                    "Ingested kernel telemetry event"
                );

                process_tree.ingest_event(&event);

                if let Some(entity) = process_tree.get_process(event.pid) {
                    if entity.blast_radius > 3.0 {
                        warn!(
                            pid = entity.pid,
                            blast_radius = entity.blast_radius,
                            "HIGH THREAT BLAST-RADIUS DETECTED: Triggering anomaly investigation"
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
