# AEGISKERNEL: NON-NEGOTIABLE ENGINEERING & SECURITY RULES

```
========================================================================================
                  AEGISKERNEL CONSTITUTION & CORE ENGINEERING DIRECTIVES
========================================================================================
```

## 1. Prime Directives & Engineering Mindset
Every line of code and configuration in AegisKernel must adhere to these inviolable axioms:
*   **Security > Features:** A feature with a potential security loophole must never be merged.
*   **Reliability > Speed:** Predictable, deterministic behavior under load outweighs raw throughput.
*   **Correctness > Assumptions:** No assumptions about kernel state, system call ordering, or network inputs.
*   **Evidence > Opinions:** All threat detection decisions must link to immutable, verifiable graph causal proofs.
*   **Simplicity > Complexity:** Do not introduce distributed abstractions where local deterministic code suffices.

---

## 2. Kernel & eBPF Safety Rules (Linux Kernel Maintainer Standards)
1.  **Strict BPF-LSM & Tracepoint Usage:** Never use raw kprobes for security enforcement. All security controls must use **BPF-LSM** hooks (`bprm_committed_creds`, `file_mprotect`, `socket_connect`) with stable ABI guarantees.
2.  **Ring Buffer Invariant:** Always use `BPF_MAP_TYPE_RINGBUF` (Linux >= 5.8) with `bpf_ringbuf_reserve` and `bpf_ringbuf_submit`. Legacy perf buffers (`BPF_MAP_TYPE_PERF_EVENT_ARRAY`) are strictly forbidden.
3.  **Zero Panic Tolerance:** In-kernel eBPF code must never crash or panic the kernel. Probes must be verified against LLVM 16+ with `-O2 -g -target bpf`.
4.  **Bounded Execution:** All loops inside eBPF must be strictly bounded with `#pragma unroll` or verified bounded iterators. Unbounded loops are grounds for immediate CI rejection.
5.  **Safe Memory Access:** Never dereference kernel pointers directly. Always use `bpf_probe_read_kernel()` and `bpf_probe_read_kernel_str()` with explicit boundary guards.
6.  **Fail-Safe Kernel Unloading:** Every eBPF program must have a clean userspace signal handler (`SIGINT`, `SIGTERM`) that detaches probes and unloads BPF maps without leaving dangling hooks.

---

## 3. Rust Codebase & Memory Safety Rules
1.  **Zero `unsafe` in Userspace Agent:** The userspace Rust ingestion agent must maintain `#![deny(unsafe_code)]` unless interacting with C foreign function interfaces (FFI) to `libbpf-sys`. Any necessary `unsafe` block must be documented with a formal `// SAFETY:` invariant proof.
2.  **Zero Memory Leaks:** Explicit RAII resource management. All network streams, file descriptors, and mapped ring buffers must drop deterministically.
3.  **Explicit Error Handling:** Never use `.unwrap()` or `.expect()` in production paths. Always use `Result<T, AegisError>` with typed error enums (`thiserror` / `anyhow`).
4.  **Zero-Copy Serialization:** Telemetry streaming must leverage zero-copy deserialization (`rkyv`, `capnp`, or `arrow`) to prevent CPU bottlenecks on high-throughput event paths.

---

## 4. AI & Neuro-Symbolic Safety Rules (AI Safety Researcher Standards)
1.  **Zero Direct Execution Rights for LLMs:** Multi-agent LLM components have **NO authority** to execute destructive OS commands (`kill`, `rm`, `iptables`, `bpf_override_return`).
2.  **Strict Neuro-Symbolic Gating:** All agent recommendations must be validated by the deterministic **Causal Invariant Checker** (First-Order Logic SMT Solver) against the live provenance graph before human display or containment suggestion.
3.  **Structured JSON Schemas Only:** LLMs must never output free-form text into control pipelines. Outputs must validate against strict, schema-enforced JSON structures (Draft-07).
4.  **Topological Prompting (Indirect Injection Immunity):** Raw system call strings, process command lines, and network payloads must never be placed into LLM system prompts without strict escaping and topological abstraction.

---

## 5. Deception & Ghost-Mirror Invariants
1.  **Strict Isolation:** Deception memory buffers must be allocated in non-executable, isolated RAM scratchpads.
2.  **Zero Leakage of Real State:** When a process is shunted into Ghost-Mirror, it must be completely blocked from seeing real host files, genuine credentials, or production network sockets.
3.  **Canary Cryptographic Integrity:** All synthetic credentials and decoy tokens must be cryptographically signed with an HMAC key rotated every 24 hours.

---

## 6. Git, CI/CD & Modification Protocol
Before every file modification:
1. Explain rationale.
2. Explain risks.
3. Explain architecture impact.
4. Explain security impact.
5. List files affected.

After every file modification:
1. Files changed.
2. What changed.
3. Why it changed.
4. Tests executed.
5. Remaining risks.
6. Rollback plan.
