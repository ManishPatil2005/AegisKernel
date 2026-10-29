# AEGISKERNEL: SYSTEM ARCHITECTURE SPECIFICATION

```
========================================================================================
                      DETAILED TECHNICAL ARCHITECTURE SPECIFICATION
========================================================================================
Classification: Production-Grade Autonomous Threat Hunting & Deception Platform
Document Version: 1.0.0
Standards: CNCF Cloud Native, NIST CSF 2.0, POSIX, Linux Kernel 5.8+ ABI
========================================================================================
```

## 1. High-Level Subsystem Topology

AegisKernel decouples high-throughput host-level instrumentation from centralized graph intelligence and neuro-symbolic reasoning across 8 distinct layers:

```
+───────────────────────────────────────────────────────────────────────────────────────────────────+
| LAYER 1: HOST KERNEL TELEMETRY & BPF-LSM                                                          |
|  - eBPF Probes: sched_process_exec, sched_process_exit, bprm_committed_creds, socket_connect      |
|  - In-Kernel Sketch: Bounded HyperLogLog Lineage Sketch in BPF_MAP_TYPE_PERCPU_ARRAY              |
|  - Transport: Zero-Copy BPF_MAP_TYPE_RINGBUF (64 MB buffer per host)                              |
+─────────────────────────────────┬─────────────────────────────────────────────────────────────────+
                                  │ Zero-Copy MMap
                                  ▼
+───────────────────────────────────────────────────────────────────────────────────────────────────+
| LAYER 2: AEGIS EDGE INGESTION AGENT (RUST)                                                        |
|  - Async Ring Buffer Worker (tokio)                                                               |
|  - Local Process Ancestry Table (pid -> ProcessContext)                                           |
|  - Telemetry Sanitizer (Regex credential/token redaction)                                         |
|  - Backpressure WAL (Local NVMe buffer for network disconnects)                                   |
|  - Serializer: Apache Arrow Flight / Cap'n Proto over mTLS 1.3                                    |
+─────────────────────────────────┬─────────────────────────────────────────────────────────────────+
                                  │ mTLS 1.3 Streaming (gRPC)
                                  ▼
+───────────────────────────────────────────────────────────────────────────────────────────────────+
| LAYER 3: DISTRIBUTED EVENT BACKBONE (REDPANDA / KAFKA)                                            |
|  - Partition Keying: (tenant_id, host_uuid)                                                       |
|  - Retention Policy: 7-day compact rolling log                                                    |
|  - Throughput: > 100,000 events/sec per broker partition                                          |
+─────────────────────────────────┬─────────────────────────────────────────────────────────────────+
                                  │ High-Throughput Consumer Group
                                  ▼
+───────────────────────────────────────────────────────────────────────────────────────────────────+
| LAYER 4: IN-MEMORY TEMPORAL GRAPH ENGINE                                                          |
|  - Engine: Memgraph / Rust petgraph distributed cluster                                           |
|  - Entities: Process, File, Socket, User                                                          |
|  - Streaming Edge Reducer: Collapses redundant syscall loops into temporal interval weights       |
|  - Real-Time Dynamic Blast-Radius Calculator (Graph Spectral Radius)                              |
+─────────────────────────────────┬─────────────────────────────────────────────────────────────────+
                                  │ Subgraph Stream
                                  ▼
+───────────────────────────────────────────────────────────────────────────────────────────────────+
| LAYER 5: CONTINUOUS-TIME TEMPORAL GNN (CT-HTGN)                                                   |
|  - Framework: PyTorch Geometric + TensorRT C++ Runtime                                            |
|  - Memory Updater: Exponential continuous-time decay (Delta t)                                    |
|  - Innovation Boundary: Evaluates anomaly entropy (Delta H > tau_entropy)                         |
|  - Latency: p99 < 5.0 ms per inference batch                                                      |
+─────────────────────────────────┬─────────────────────────────────────────────────────────────────+
                                  │ Anomaly Subgraph Trigger
                                  ▼
+───────────────────────────────────────────────────────────────────────────────────────────────────+
| LAYER 6: NEURO-SYMBOLIC MULTI-AGENT AI SWARM                                                      |
|  - Triaging Agent (Fast L1 screening via local quantized SLM)                                     |
|  - Deep Hunting Agent (Causal provenance traversal and hypothesis synthesis)                     |
|  - Adversary Profiler (Deterministic MITRE ATT&CK mapping)                                        |
|  - Causal Verification Gate: First-Order Logic (FOL) SMT Solver (Z3 / CVC5)                       |
|  - Human Approval Gate: WebAuthn cryptographic multi-signature quorum                             |
+───────────────────┬───────────────────────────────────────────────────────────┬───────────────────+
                    │ Shunting Directives                                       │ Real-Time WSS
                    ▼                                                           ▼
+─────────────────────────────────────────────+   +─────────────────────────────────────────────────+
| LAYER 7: GHOST-MIRROR IN-KERNEL DECEPTION   |   | LAYER 8: SOC THREAT VISUALIZATION PLATFORM      |
|  - BPF-LSM Return Override                  |   |  - Next.js 15 + React 19 Frontend               |
|  - Copy-on-Write (CoW) Memory Shunting      |   |  - WebGL / Three.js 60 FPS Graph Canvas         |
|  - Cryptographic Canary Ingestion Traps     |   |  - Interactive Temporal Scrubbing Timeline      |
+─────────────────────────────────────────────+   +─────────────────────────────────────────────────+
```

---

## 2. In-Kernel Telemetry Data Contracts (Binary C Structs)

All events emitted from kernel space to userspace adhere to fixed-width, 64-bit aligned binary structures:

```c
// Event Type Enumeration
enum aegis_event_type {
    AEGIS_EVENT_PROCESS_EXEC  = 1,
    AEGIS_EVENT_PROCESS_EXIT  = 2,
    AEGIS_EVENT_PRIVILEGE_ESC = 3,
    AEGIS_EVENT_FILE_MODIFY   = 4,
    AEGIS_EVENT_SOCKET_CONN   = 5,
    AEGIS_EVENT_CANARY_HIT    = 6,
};

// Core Process Telemetry Record (64-byte aligned)
struct aegis_process_event {
    uint64_t timestamp_ns;          // Kernel monotonic timestamp
    uint32_t pid;                   // Process ID
    uint32_t tgid;                  // Thread Group ID
    uint32_t ppid;                  // Parent Process ID
    uint32_t uid;                   // User ID
    uint32_t gid;                   // Group ID
    uint32_t event_type;            // enum aegis_event_type
    uint64_t cgroup_id;             // Container cgroup identifier
    uint64_t lineage_hash;          // In-kernel HyperLogLog ancestry sketch
    char comm[16];                  // Process executable shortname
    char filename[256];             // Full path to binary executable
};
```

---

## 3. Provenance Graph Data Model & Schema

The graph intelligence layer models OS execution as a Directed Acyclic Graph (DAG) $\mathcal{G} = (\mathcal{V}, \mathcal{E})$:

### Vertex Types ($\mathcal{V}$):
1.  **Process Node:** `(node_id, pid, ppid, comm, binary_hash, uid, start_time, blast_radius)`
2.  **File Node:** `(node_id, inode, path, file_type, entropy, sha256_hash)`
3.  **Socket Node:** `(node_id, src_ip, dst_ip, src_port, dst_port, protocol, state)`
4.  **User Node:** `(node_id, uid, username, privilege_tier)`

### Edge Types ($\mathcal{E}$):
*   `FORKED(parent, child, timestamp)`
*   `EXECUTED(process, file, timestamp)`
*   `WROTE(process, file, bytes_written, timestamp)`
*   `READ(process, file, bytes_read, timestamp)`
*   `CONNECTED_TO(process, socket, timestamp)`
*   `ESCALATED_TO(process, user, timestamp)`

---

## 4. Continuous-Time Temporal GNN Formulation

Let an incoming kernel event at time $t$ be $e = (u, v, t, \mathbf{x})$, where $u, v \in \mathcal{V}$ and $\mathbf{x} \in \mathbb{R}^d$.

1.  **Continuous Time Decay:**
    $$\Delta t_u = t - t_{\text{last\_event}}(u)$$
2.  **Memory Vector Update:**
    $$\mathbf{m}_u(t) = \text{MLP}_{\text{msg}}\left(\mathbf{s}_u(t^-) \parallel \mathbf{s}_v(t^-) \parallel \phi(\Delta t_u) \parallel \mathbf{x}\right)$$
    $$\mathbf{s}_u(t) = \text{GRU}\left(\mathbf{m}_u(t), \mathbf{s}_u(t^-)\right)$$
3.  **Temporal Attention Operator:**
    $$\mathbf{z}_u(t) = \sum_{v \in \mathcal{N}(u)} \alpha_{uv} \ \mathbf{W}_V \left(\mathbf{s}_v(t) \parallel \phi(t - t_e)\right)$$
    where $\alpha_{uv} = \text{Softmax}\left(\frac{(\mathbf{W}_Q \mathbf{s}_u)(\mathbf{W}_K \mathbf{s}_v)^T}{\sqrt{d_k}}\right)$.

---

## 5. Neuro-Symbolic Causal Verification Gate

The SMT Verification Engine enforces formal invariant checks over containment recommendations.

```
+───────────────────────────+
| LLM Agent Output (JSON)   |
| "Kill PID 4092 & Isolate" |
+─────────────┬─────────────+
              │
              ▼
+───────────────────────────────────────────────────────────+
| First-Order Logic AST Translator                          |
| Formula: Phi_kill(4092) = IsCompromised(4092)            |
|                           AND Reachable(Attacker, 4092)   |
|                           AND NOT IsCrownJewel(4092)      |
+─────────────────────────────┬─────────────────────────────+
                              │
                              ▼
+───────────────────────────────────────────────────────────+
| Z3 SMT Solver / Automated Theorem Prover                  |
| - Ingests Live Subgraph Axioms                            |
| - Verifies Satisfiability of Phi_kill                     |
+─────────────────────────────┬─────────────────────────────+
                              │
               ┌──────────────┴──────────────┐
               ▼                             ▼
        [ SAT: Verified ]            [ UNSAT: Rejected ]
               │                             │
               ▼                             ▼
    [ Submit to BPF Enforcer ]      [ Flag Hallucination ]
```
