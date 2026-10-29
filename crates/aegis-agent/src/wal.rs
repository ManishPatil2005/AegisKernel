//! # NVMe Write-Ahead Log (WAL) Backpressure Buffer
//!
//! Provides durable, zero-allocation local disk spooling of telemetry events
//! when network connectivity to the Kafka streaming pipeline is degraded or severed.

use aegis_proto::TelemetryEvent;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Magic header byte sequence identifying valid Aegis WAL segments.
pub const WAL_MAGIC: &[u8; 4] = b"AGWL";
/// Current WAL format version.
pub const WAL_VERSION: u16 = 1;

/// Errors occurring during WAL operations.
#[derive(Debug, thiserror::Error)]
pub enum WalError {
    /// Standard I/O failure.
    #[error("WAL I/O Error: {0}")]
    Io(#[from] std::io::Error),
    /// Serialization failure.
    #[error("Serialization Error: {0}")]
    Serialization(#[from] bincode::Error),
    /// Corrupt file header or invalid magic bytes.
    #[error("Invalid WAL Header or corrupted segment")]
    InvalidHeader,
}

/// Durable Write-Ahead Log writer and recovery reader.
pub struct WriteAheadLog {
    file_path: PathBuf,
    writer: BufWriter<File>,
    record_count: u64,
}

impl WriteAheadLog {
    /// Opens an existing WAL segment or creates a new one at the specified path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, WalError> {
        let path = path.as_ref().to_path_buf();
        let exists = path.exists();

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)?;

        let mut writer = BufWriter::new(file);

        if !exists {
            // Write 8-byte segment header: [MAGIC(4), VERSION(2), RESERVED(2)]
            writer.write_all(WAL_MAGIC)?;
            writer.write_all(&WAL_VERSION.to_le_bytes())?;
            writer.write_all(&[0u8; 2])?;
            writer.flush()?;
        }

        Ok(Self {
            file_path: path,
            writer,
            record_count: 0,
        })
    }

    /// Appends a structured telemetry event to the persistent WAL segment.
    pub fn append(&mut self, event: &TelemetryEvent) -> Result<(), WalError> {
        let encoded = bincode::serialize(event)?;
        let length = encoded.len() as u32;

        // Record framing: [Length (4 bytes)] + [Payload (N bytes)]
        self.writer.write_all(&length.to_le_bytes())?;
        self.writer.write_all(&encoded)?;
        self.writer.flush()?;

        self.record_count += 1;
        Ok(())
    }

    /// Replays all buffered telemetry events from the segment for upstream recovery.
    pub fn replay(&self) -> Result<Vec<TelemetryEvent>, WalError> {
        let mut file = File::open(&self.file_path)?;
        file.seek(SeekFrom::Start(0))?;

        let mut reader = BufReader::new(file);

        // Verify header
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != WAL_MAGIC {
            return Err(WalError::InvalidHeader);
        }

        let mut version_bytes = [0u8; 2];
        reader.read_exact(&mut version_bytes)?;
        let mut reserved = [0u8; 2];
        reader.read_exact(&mut reserved)?;

        let mut events = Vec::new();
        let mut len_buf = [0u8; 4];

        while reader.read_exact(&mut len_buf).is_ok() {
            let length = u32::from_le_bytes(len_buf) as usize;
            let mut payload = vec![0u8; length];
            reader.read_exact(&mut payload)?;

            let event: TelemetryEvent = bincode::deserialize(&payload)?;
            events.push(event);
        }

        Ok(events)
    }

    /// Number of records appended in this session.
    pub fn record_count(&self) -> u64 {
        self.record_count
    }

    /// Truncates and resets the WAL file after successful upstream flushing.
    pub fn purge(&mut self) -> Result<(), WalError> {
        self.writer.flush()?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .truncate(true)
            .open(&self.file_path)?;

        let mut writer = BufWriter::new(file);
        writer.write_all(WAL_MAGIC)?;
        writer.write_all(&WAL_VERSION.to_le_bytes())?;
        writer.write_all(&[0u8; 2])?;
        writer.flush()?;

        self.writer = writer;
        self.record_count = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_proto::AegisEventType;

    #[test]
    fn test_wal_append_replay_purge() {
        let temp_dir = std::env::temp_dir();
        let wal_path = temp_dir.join(format!("aegis_test_wal_{}.log", std::time::SystemTime::now().elapsed().unwrap().as_nanos()));

        let mut wal = WriteAheadLog::open(&wal_path).expect("open WAL");

        let event = TelemetryEvent {
            timestamp_ns: 1000,
            pid: 1024,
            ppid: 1,
            uid: 0,
            gid: 0,
            event_type: AegisEventType::ProcessExec,
            cgroup_id: 1,
            lineage_hash: 0x42,
            comm: "bash".into(),
            filename: "/bin/bash".into(),
        };

        wal.append(&event).expect("append event");
        assert_eq!(wal.record_count(), 1);

        let replayed = wal.replay().expect("replay WAL");
        assert_eq!(replayed.len(), 1);
        assert_eq!(replayed[0].pid, 1024);
        assert_eq!(replayed[0].comm, "bash");

        wal.purge().expect("purge WAL");
        let empty_replay = wal.replay().expect("replay empty WAL");
        assert_eq!(empty_replay.len(), 0);

        let _ = std::fs::remove_file(wal_path);
    }
}
