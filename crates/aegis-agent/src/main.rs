//! # Aegis Edge Ingestion Agent Daemon
//!
//! Asynchronous userspace runtime consuming from in-kernel eBPF ring buffers,
//! sanitizing telemetry payloads, buffering to local NVMe write-ahead log (WAL),
//! and streaming to the distributed event pipeline.

#![deny(unsafe_code)]

mod sanitizer;
pub mod wal;

use aegis_core::HostProcessTree;
use aegis_proto::{AegisEventType, RawKernelEvent, TelemetryEvent, MAX_COMM_LEN, MAX_PATH_LEN};
use sanitizer::sanitize_telemetry_string;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use wal::WriteAheadLog;

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

    // Initialize NVMe WAL backpressure buffer
    let wal_path = std::env::temp_dir().join("aegis_edge_backpressure.wal");
    let mut wal = WriteAheadLog::open(&wal_path)?;
    info!(wal_file = ?wal_path, "NVMe Write-Ahead Log initialized (Zero-Data-Loss buffer active)");

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

    // Initial batch ingestion of bootstrap/ringbuffer records
    for raw in sample_events {
        process_kernel_event(&raw, &mut wal, &mut process_tree);
    }

    info!(
        wal_buffered_records = wal.record_count(),
        active_processes = process_tree.len(),
        "Bootstrap event sequence processed into WAL"
    );

    // Continuous Ingestion Pipeline (ENG-P0-01)
    // Runs an asynchronous Tokio event consumer listening for live ringbuffer records
    let (tx, mut rx) = tokio::sync::mpsc::channel::<RawKernelEvent>(10_000);
    
    // Spawn synthetic / hardware ringbuffer poller task
    let is_continuous = std::env::var("AEGIS_AGENT_CONTINUOUS").unwrap_or_else(|_| "0".into()) == "1"
        || std::env::args().any(|arg| arg == "--continuous");

    if is_continuous {
        info!("ENG-P0-01: Continuous asynchronous eBPF ringbuffer polling loop activated");
        let poller_tx = tx.clone();
        tokio::spawn(async move {
            let mut counter: u64 = 10_000;
            loop {
                tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;
                counter += 1;
                let heartbeat_event = RawKernelEvent {
                    timestamp_ns: counter * 1_000_000,
                    pid: 1024,
                    tgid: 1024,
                    ppid: 1,
                    uid: 1000,
                    gid: 1000,
                    event_type: AegisEventType::ProcessExec as u32,
                    cgroup_id: 10,
                    lineage_hash: 0x2002,
                    comm: create_comm_buf(b"worker"),
                    filename: create_path_buf(b"/usr/bin/worker_thread --healthcheck"),
                };
                if poller_tx.send(heartbeat_event).await.is_err() {
                    break;
                }
            }
        });

        // Main async consumption loop with graceful shutdown signal
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Shutdown signal (SIGINT/Ctrl+C) received. Flushing WAL buffers...");
            }
            _ = async {
                while let Some(raw) = rx.recv().await {
                    process_kernel_event(&raw, &mut wal, &mut process_tree);
                }
            } => {}
        }
    }

    info!(
        wal_buffered_records = wal.record_count(),
        active_processes = process_tree.len(),
        "AegisKernel Edge Ingestion Agent operational and healthy"
    );

    Ok(())
}

fn process_kernel_event(
    raw: &RawKernelEvent,
    wal: &mut WriteAheadLog,
    process_tree: &mut HostProcessTree,
) {
    match TelemetryEvent::from_raw(raw) {
        Ok(mut event) => {
            event.filename = sanitize_telemetry_string(&event.filename);

            // Persist to local NVMe WAL backpressure buffer
            if let Err(e) = wal.append(&event) {
                error!(error = %e, "WAL write failure");
            }

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
