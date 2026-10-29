# AEGISKERNEL: DETAILED SYSTEM DESIGN SPECIFICATION

```
========================================================================================
                      DETAILED COMPONENT DESIGN & INTERFACE CONTRACTS
========================================================================================
Classification: Domain-Driven Design (DDD) & Component Architecture
Version: 1.0.0
========================================================================================
```

## 1. Domain-Driven Design (DDD) Bounded Contexts

AegisKernel is partitioned into four primary bounded contexts:

```
+───────────────────────────────────────────────────────────────────────────────────────+
|                               BOUNDED CONTEXT TOPOLOGY                                |
|                                                                                       |
|  [ KERNEL INSTRUMENTATION CONTEXT ]       [ GRAPH CAUSALITY CONTEXT ]                 |
|  - eBPF Probes & Maps                     - In-Memory Provenance Graph                |
|  - RingBuffer Allocator                   - Subgraph Extractor                        |
|  - Ghost-Mirror Memory Shunt              - Blast-Radius Metric Calculator            |
|                                                                                       |
|  [ NEURO-SYMBOLIC REASONING CONTEXT ]     [ DECEPTION & CONTAINMENT CONTEXT ]         |
|  - Continuous-Time Dynamic GNN            - Canary Generator                          |
|  - Specialist Multi-Agent Swarm           - BPF-LSM Override Enforcer                 |
|  - SMT First-Order Logic Verifier         - WebAuthn Cryptographic Quorum             |
+───────────────────────────────────────────────────────────────────────────────────────+
```

---

## 2. Core Service Interfaces & Sequence Flows

### 2.1 Telemetry Ingestion to Containment Sequence Diagram

```
[ Host Kernel ]       [ Rust Agent ]      [ Kafka Broker ]     [ Graph Engine ]     [ AI Swarm / SMT ]
       │                    │                    │                    │                     │
       │ (1) BPF RingBuf    │                    │                    │                     │
       ├───────────────────►│                    │                    │                     │
       │                    │ (2) mTLS Stream    │                    │                     │
       │                    ├───────────────────►│                    │                     │
       │                    │                    │ (3) Batch Ingest   │                     │
       │                    │                    ├───────────────────►│                     │
       │                    │                    │                    │ (4) Delta H > tau   │
       │                    │                    │                    ├────────────────────►│
       │                    │                    │                    │                     │ (5) SMT Proof
       │                    │                    │                    │                     │     Verified
       │ (6) BPF Shunt      │                    │                    │◄────────────────────┤
       │◄───────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Rust Ingestion Agent Design (`aegis-agent`)

### 3.1 Modular Structure
*   `aegis-agent::bpf`: Manages eBPF lifecycle, CO-RE loading via `libbpf-rs` or `aya`, and ring-buffer attachment.
*   `aegis-agent::sanitizer`: High-throughput regex masking engine redacting sensitive credentials.
*   `aegis-agent::wal`: NVMe write-ahead log providing durable local backpressure buffering.
*   `aegis-agent::transport`: Asynchronous gRPC streaming client connecting to the distributed Kafka pipeline.

### 3.2 Threading & Concurrency Model
The Rust agent employs a dedicated thread pool:
1.  **Thread 1 (Kernel Ring Reader):** Pinned to CPU core with `SCHED_FIFO` priority, reading directly from the memory-mapped BPF ring buffer.
2.  **Threads 2–4 (Worker Pool):** Async `tokio` worker threads executing deserialization, regex sanitization, and lineage hash verification.
3.  **Thread 5 (Network Streamer):** Manages gRPC client connection with automatic backoff and reconnection logic.

---

## 4. Multi-Agent Swarm Inter-Service Contract (JSON Schema)

All inter-agent messages conform to the following JSON Schema:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "AegisAgentMessage",
  "type": "object",
  "properties": {
    "message_id": { "type": "string", "format": "uuid" },
    "source_agent": { "type": "string", "enum": ["triager", "hunter", "profiler", "gatekeeper"] },
    "timestamp_ns": { "type": "integer" },
    "target_subgraph_id": { "type": "string" },
    "confidence_score": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
    "epistemic_uncertainty": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
    "mitre_techniques": {
      "type": "array",
      "items": { "type": "string", "pattern": "^T[0-9]{4}(\\.[0-9]{3})?$" }
    },
    "fol_causal_proof": { "type": "string" },
    "containment_proposal": {
      "type": "object",
      "properties": {
        "action": { "type": "string", "enum": ["shunt_process", "isolate_network", "none"] },
        "target_pid": { "type": "integer" }
      },
      "required": ["action", "target_pid"]
    }
  },
  "required": ["message_id", "source_agent", "confidence_score", "fol_causal_proof", "containment_proposal"]
}
```
