//! # Aegis Core Domain Logic & Security Primitives
//!
//! Provides in-memory process ancestry tracking, dynamic attack blast-radius
//! quantification ($\mathcal{R}_{\text{blast}}$), and formal causal reachability checks.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::collections::{HashMap, HashSet};
use aegis_proto::{AegisEventType, TelemetryEvent};

/// Dynamic context representing an active operating system process entity.
#[derive(Debug, Clone)]
pub struct ProcessEntity {
    /// Process ID.
    pub pid: u32,
    /// Parent Process ID.
    pub ppid: u32,
    /// Real User ID.
    pub uid: u32,
    /// Binary executable name.
    pub comm: String,
    /// Full binary path.
    pub filename: String,
    /// Child process IDs spawned by this entity.
    pub children: HashSet<u32>,
    /// Sockets touched by this process.
    pub connected_sockets: HashSet<String>,
    /// Instantaneous threat blast-radius score.
    pub blast_radius: f64,
}

/// In-memory graph engine maintaining local host process trees and calculating
/// real-time threat propagation metrics.
#[derive(Debug, Default)]
pub struct HostProcessTree {
    processes: HashMap<u32, ProcessEntity>,
}

impl HostProcessTree {
    /// Creates a new, empty host process tree.
    pub fn new() -> Self {
        Self {
            processes: HashMap::new(),
        }
    }

    /// Ingests a validated telemetry event and updates the internal causal DAG.
    pub fn ingest_event(&mut self, event: &TelemetryEvent) {
        match event.event_type {
            AegisEventType::ProcessExec => {
                let entity = ProcessEntity {
                    pid: event.pid,
                    ppid: event.ppid,
                    uid: event.uid,
                    comm: event.comm.clone(),
                    filename: event.filename.clone(),
                    children: HashSet::new(),
                    connected_sockets: HashSet::new(),
                    blast_radius: 0.0,
                };

                // Link to parent
                if let Some(parent) = self.processes.get_mut(&event.ppid) {
                    parent.children.insert(event.pid);
                }

                self.processes.insert(event.pid, entity);
                self.recalculate_blast_radius(event.pid);
            }
            AegisEventType::ProcessExit => {
                self.processes.remove(&event.pid);
                // Clean up parent references
                if let Some(parent) = self.processes.get_mut(&event.ppid) {
                    parent.children.remove(&event.pid);
                }
            }
            AegisEventType::PrivilegeEscalation => {
                if let Some(entity) = self.processes.get_mut(&event.pid) {
                    entity.uid = event.uid;
                    self.recalculate_blast_radius(event.pid);
                }
            }
            _ => {}
        }
    }

    /// Recalculates the dynamic attack blast-radius score ($\mathcal{R}_{\text{blast}}$)
    /// based on process hierarchy depth, privilege tier, and spawned children.
    ///
    /// Formula:
    /// $$\mathcal{R}_{\text{blast}} = w_{\text{priv}} \times (1 + \ln(1 + |\text{children}|))$$
    pub fn recalculate_blast_radius(&mut self, pid: u32) {
        let (children_count, is_root) = match self.processes.get(&pid) {
            Some(p) => (p.children.len(), p.uid == 0),
            None => return,
        };

        let privilege_weight = if is_root { 3.5 } else { 1.0 };
        let radius = privilege_weight * (1.0 + (1.0 + children_count as f64).ln());

        if let Some(p) = self.processes.get_mut(&pid) {
            p.blast_radius = radius;
        }
    }

    /// Evaluates whether a causal path exists between an origin process and a target process.
    pub fn is_causally_reachable(&self, origin_pid: u32, target_pid: u32) -> bool {
        if origin_pid == target_pid {
            return true;
        }

        let mut visited = HashSet::new();
        let mut queue = vec![origin_pid];

        while let Some(current) = queue.pop() {
            if current == target_pid {
                return true;
            }

            if visited.insert(current) {
                if let Some(entity) = self.processes.get(&current) {
                    for &child in &entity.children {
                        if !visited.contains(&child) {
                            queue.push(child);
                        }
                    }
                }
            }
        }

        false
    }

    /// Retrieves an entity reference by process ID.
    pub fn get_process(&self, pid: u32) -> Option<&ProcessEntity> {
        self.processes.get(&pid)
    }

    /// Total count of active tracked processes.
    pub fn len(&self) -> usize {
        self.processes.len()
    }

    /// Checks if the tree is currently empty.
    pub fn is_empty(&self) -> bool {
        self.processes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_tree_causality() {
        let mut tree = HostProcessTree::new();

        // 1. Root init process
        let init_event = TelemetryEvent {
            timestamp_ns: 100,
            pid: 1,
            ppid: 0,
            uid: 0,
            gid: 0,
            event_type: AegisEventType::ProcessExec,
            cgroup_id: 1,
            lineage_hash: 0,
            comm: "systemd".into(),
            filename: "/usr/lib/systemd/systemd".into(),
        };
        tree.ingest_event(&init_event);

        // 2. SSHD spawned by init
        let sshd_event = TelemetryEvent {
            timestamp_ns: 200,
            pid: 1000,
            ppid: 1,
            uid: 0,
            gid: 0,
            event_type: AegisEventType::ProcessExec,
            cgroup_id: 1,
            lineage_hash: 0,
            comm: "sshd".into(),
            filename: "/usr/sbin/sshd".into(),
        };
        tree.ingest_event(&sshd_event);

        // 3. Bash shell spawned by SSHD
        let bash_event = TelemetryEvent {
            timestamp_ns: 300,
            pid: 2000,
            ppid: 1000,
            uid: 1000,
            gid: 1000,
            event_type: AegisEventType::ProcessExec,
            cgroup_id: 1,
            lineage_hash: 0,
            comm: "bash".into(),
            filename: "/bin/bash".into(),
        };
        tree.ingest_event(&bash_event);

        // Causal assertions
        assert!(tree.is_causally_reachable(1, 2000));
        assert!(tree.is_causally_reachable(1000, 2000));
        assert!(!tree.is_causally_reachable(2000, 1)); // Time arrow cannot invert
    }

    #[test]
    fn test_blast_radius_escalation() {
        let mut tree = HostProcessTree::new();

        let event = TelemetryEvent {
            timestamp_ns: 100,
            pid: 500,
            ppid: 1,
            uid: 1000, // Unprivileged user
            gid: 1000,
            event_type: AegisEventType::ProcessExec,
            cgroup_id: 1,
            lineage_hash: 0,
            comm: "malware".into(),
            filename: "/tmp/malware".into(),
        };
        tree.ingest_event(&event);

        let initial_radius = tree.get_process(500).unwrap().blast_radius;

        // Privilege escalation event
        let priv_event = TelemetryEvent {
            timestamp_ns: 150,
            pid: 500,
            ppid: 1,
            uid: 0, // Escalated to root!
            gid: 0,
            event_type: AegisEventType::PrivilegeEscalation,
            cgroup_id: 1,
            lineage_hash: 0,
            comm: "malware".into(),
            filename: "/tmp/malware".into(),
        };
        tree.ingest_event(&priv_event);

        let escalated_radius = tree.get_process(500).unwrap().blast_radius;
        assert!(escalated_radius > initial_radius * 3.0);
    }
}
