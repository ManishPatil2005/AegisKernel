# AEGISKERNEL: PERSISTENT PROJECT MEMORY & ARCHITECTURAL STATE

```
========================================================================================
                  AEGISKERNEL ACTIVE MEMORY & STATE REGISTRY
========================================================================================
Last Synchronized: October 29, 2026
System Status: PHASE 1 DAY 1 - FOUNDATIONAL GOVERNANCE & DOCUMENTATION SPRINT
Active Target Directory: D:\internship project  soc
========================================================================================
```

## 1. Project Identity & Vision
*   **Project Name:** AegisKernel
*   **Classification:** Autonomous Agentic Threat Hunting and Kernel-Level Deception Platform
*   **Mission:** Eradicate alert fatigue and shrink MTTR to sub-second wire speed by coupling non-invasive eBPF in-kernel telemetry with continuous-time temporal graph learning, neuro-symbolic multi-agent reasoning, and transparent in-kernel deception ("Ghost-Mirror").
*   **Dual-Track Objective:** 
    1. Enterprise-grade production platform ready for SOC deployment.
    2. Top-tier academic research artifact targeting USENIX Security / IEEE S&P and 5 PCT patent disclosures.

---

## 2. Core Architectural Pillars
1.  **eBPF Telemetry Engine (Host Kernel):** BPF-LSM (`bprm_committed_creds`, `file_mprotect`, `socket_connect`) with bounded in-kernel sketches and zero-copy `BPF_MAP_TYPE_RINGBUF`.
2.  **Aegis Ingestion Agent (Host Userspace):** Memory-safe asynchronous Rust (`tokio`), zero `unsafe`, zero-copy binary serialization (Arrow / Cap'n Proto), edge noise filtering, and NVMe backpressure buffering.
3.  **Distributed Event Pipeline:** Redpanda / Kafka cluster partitioned by `(tenant_id, host_uuid)` with TLS 1.3 and mTLS SPIFFE/SPIRE authentication.
4.  **In-Memory Temporal Graph Engine:** High-throughput streaming graph store (Memgraph / Rust petgraph) maintaining directed causal edges between Process, File, Socket, and User entities.
5.  **Continuous-Time Dynamic GNN (CT-HTGN):** Streaming graph neural network with continuous exponential decay memory updater evaluating localized anomaly innovation ($\Delta \mathcal{H}$).
6.  **Neuro-Symbolic Multi-Agent AI Swarm:** 4-tier specialist swarm (Triage, Hunting, Profiling, Verification) constrained by First-Order Logic (FOL) SMT solver proofs. Zero direct unverified execution.
7.  **Ghost-Mirror In-Kernel Deception:** `bpf_override_return()` and copy-on-write memory shunting that diverts malicious processes into synthetic memory while returning authentic success codes.
8.  **Threat Visualization Platform:** Next.js 15 + React 19 SOC command dashboard with WebGL hardware-accelerated dynamic graph rendering, live replay timeline, and WebAuthn containment execution.

---

## 3. Technology Stack & Toolchain Standards
*   **Kernel Instrumentation:** C (clang/LLVM 16+), BPF CO-RE, BTF, `libbpf-rs` / `aya`
*   **Edge Agent:** Rust (2021 edition), `tokio`, `axum`, `capnp`, `prometheus-client`
*   **Streaming & Message Broker:** Redpanda / Apache Kafka (Protobuf schemas)
*   **Graph Intelligence:** Memgraph / Cypher, Apache Arrow Flight, C++ / Rust
*   **AI & Machine Learning:** Python 3.11, PyTorch Geometric (PyG), TensorRT, vLLM, ONNX Runtime
*   **Neuro-Symbolic Gate:** Z3 Theorem Prover / CVC5 SMT Solver, First-Order Logic AST
*   **Frontend Dashboard:** TypeScript, Next.js 15, React 19, Tailwind CSS, Three.js / WebGL
*   **Observability:** OpenTelemetry (OTel), Prometheus, Grafana, Tempo, Loki
*   **DevSecOps:** GitHub Actions, CodeQL, Semgrep, Trivy, Syft, Cosign

---

## 4. Key Decisions & Immutable Invariants
*   *ADR-0001 (Kernel Probes):* BPF-LSM mandated over kprobes for all security-critical enforcement.
*   *ADR-0002 (Buffer Architecture):* BPF Ring Buffer (`BPF_MAP_TYPE_RINGBUF`) strictly mandated over legacy perf buffers.
*   *ADR-0003 (Language Discipline):* Edge agent written purely in safe Rust; zero unvalidated `unsafe` blocks.
*   *ADR-0004 (AI Containment Gate):* LLMs are strictly proposal engines; all automated actions require SMT solver causal proofs.
*   *ADR-0005 (Prompt Isolation):* Raw strings stripped from LLM prompts to guarantee indirect prompt injection immunity.
