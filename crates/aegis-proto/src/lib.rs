//! # Aegis Protocol & Telemetry Data Contracts
//!
//! Provides binary-compatible telemetry event structs, event type enumerations,
//! and validation routines connecting in-kernel eBPF probes to the userspace
//! ingestion pipeline.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};

/// Maximum byte length for a binary executable path in telemetry events.
pub const MAX_PATH_LEN: usize = 256;
/// Maximum byte length for an executable process command name.
pub const MAX_COMM_LEN: usize = 16;

/// High-level event classification emitted by in-kernel eBPF instrumentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum AegisEventType {
    /// Binary execution via `sched_process_exec`.
    ProcessExec = 1,
    /// Process termination via `sched_process_exit`.
    ProcessExit = 2,
    /// Privilege transition via BPF-LSM `bprm_committed_creds`.
    PrivilegeEscalation = 3,
    /// Mutating memory protection via BPF-LSM `file_mprotect`.
    MemoryProtect = 4,
    /// Outbound network connection via `socket_connect`.
    SocketConnect = 5,
    /// Synthetic canary access detected (Ghost-Mirror trigger).
    CanaryHit = 6,
    /// In-kernel process redirection into synthetic shadow memory.
    GhostShunt = 7,
}

impl TryFrom<u32> for AegisEventType {
    type Error = ProtoError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ProcessExec),
            2 => Ok(Self::ProcessExit),
            3 => Ok(Self::PrivilegeEscalation),
            4 => Ok(Self::MemoryProtect),
            5 => Ok(Self::SocketConnect),
            6 => Ok(Self::CanaryHit),
            7 => Ok(Self::GhostShunt),
            other => Err(ProtoError::InvalidEventType(other)),
        }
    }
}

/// Fixed-width, C-compatible binary record emitted by the in-kernel eBPF ring buffer.
///
/// Designed with strict 64-bit boundary alignment to prevent kernel-to-userspace padding faults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct RawKernelEvent {
    /// Monotonic timestamp in nanoseconds since host boot.
    pub timestamp_ns: u64,
    /// Process ID.
    pub pid: u32,
    /// Thread Group ID.
    pub tgid: u32,
    /// Parent Process ID.
    pub ppid: u32,
    /// Real User ID.
    pub uid: u32,
    /// Real Group ID.
    pub gid: u32,
    /// Event type code (corresponds to [`AegisEventType`]).
    pub event_type: u32,
    /// Linux cgroup identifier for container isolation.
    pub cgroup_id: u64,
    /// In-kernel HyperLogLog process ancestry sketch hash.
    pub lineage_hash: u64,
    /// Process comm shortname (null-padded).
    pub comm: [u8; MAX_COMM_LEN],
    /// Binary executable full file path (null-padded).
    pub filename: [u8; MAX_PATH_LEN],
}

/// Higher-level parsed and sanitized telemetry event for downstream graph intelligence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryEvent {
    /// Monotonic timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Process ID.
    pub pid: u32,
    /// Parent Process ID.
    pub ppid: u32,
    /// User ID.
    pub uid: u32,
    /// Group ID.
    pub gid: u32,
    /// High-level event category.
    pub event_type: AegisEventType,
    /// Container cgroup ID.
    pub cgroup_id: u64,
    /// Ancestry lineage hash for graph reachability verification.
    pub lineage_hash: u64,
    /// Process shortname string.
    pub comm: String,
    /// Executable file path string.
    pub filename: String,
}

impl TelemetryEvent {
    /// Converts and validates a raw kernel ring buffer record into a structured telemetry event.
    pub fn from_raw(raw: &RawKernelEvent) -> Result<Self, ProtoError> {
        let event_type = AegisEventType::try_from(raw.event_type)?;

        // Extract null-terminated comm string
        let comm_len = raw.comm.iter().position(|&c| c == 0).unwrap_or(MAX_COMM_LEN);
        let comm = String::from_utf8_lossy(&raw.comm[..comm_len]).to_string();

        // Extract null-terminated filename string
        let file_len = raw.filename.iter().position(|&c| c == 0).unwrap_or(MAX_PATH_LEN);
        let filename = String::from_utf8_lossy(&raw.filename[..file_len]).to_string();

        Ok(Self {
            timestamp_ns: raw.timestamp_ns,
            pid: raw.pid,
            ppid: raw.ppid,
            uid: raw.uid,
            gid: raw.gid,
            event_type,
            cgroup_id: raw.cgroup_id,
            lineage_hash: raw.lineage_hash,
            comm,
            filename,
        })
    }
}

/// Errors occurring during telemetry serialization or parsing.
#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    /// The event type code does not correspond to a known variant.
    #[error("Unknown or invalid event type code: {0}")]
    InvalidEventType(u32),
    /// Deserialization failure.
    #[error("Failed to deserialize binary event: {0}")]
    DeserializationError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_conversion() {
        assert_eq!(AegisEventType::try_from(1).unwrap(), AegisEventType::ProcessExec);
        assert_eq!(AegisEventType::try_from(6).unwrap(), AegisEventType::CanaryHit);
        assert!(AegisEventType::try_from(99).is_err());
    }

    #[test]
    fn test_raw_event_parsing() {
        let mut raw = RawKernelEvent {
            timestamp_ns: 1_000_000_000,
            pid: 1024,
            tgid: 1024,
            ppid: 1,
            uid: 0,
            gid: 0,
            event_type: 1,
            cgroup_id: 42,
            lineage_hash: 0xDEADBEEF,
            comm: [0; MAX_COMM_LEN],
            filename: [0; MAX_PATH_LEN],
        };

        let comm_bytes = b"bash";
        raw.comm[..comm_bytes.len()].copy_from_slice(comm_bytes);

        let file_bytes = b"/usr/bin/bash";
        raw.filename[..file_bytes.len()].copy_from_slice(file_bytes);

        let event = TelemetryEvent::from_raw(&raw).expect("valid conversion");
        assert_eq!(event.comm, "bash");
        assert_eq!(event.filename, "/usr/bin/bash");
        assert_eq!(event.event_type, AegisEventType::ProcessExec);
        assert_eq!(event.pid, 1024);
        assert_eq!(event.uid, 0);
    }
}
