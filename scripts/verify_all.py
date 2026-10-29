#!/usr/bin/env python3
"""
AegisKernel: Unified Master Verification & Health Certification Harness
========================================================================
Executes an end-to-end verification of all subsystems:
- Formal Methods & SMT Solvers (Z3 Crown Jewel Invariants)
- Topological Prompt Isolation Engine (Anti-Jailbreak)
- Bayesian Consensus Engine
- Causal Graph Reducer & Blast Radius Metrics
- CT-HTGN Anomaly Evaluator
- Ghost-Mirror In-Kernel Deception Orchestrator
- Red Team Adversarial Drills (BPFDoor & Ransomware)
- Live Agency & SOC HTTP Endpoints
"""

import sys
import os
import time
import subprocess
import urllib.request
import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent

TEST_SUITES = [
    {
        "name": "Z3 Neuro-Symbolic SMT Proof Gate",
        "cmd": [sys.executable, str(ROOT_DIR / "services" / "ai-swarm" / "swarm.py")],
        "subsystem": "AI Swarm"
    },
    {
        "name": "Topological Prompt Isolation (Indirect Injection Defense)",
        "cmd": [sys.executable, str(ROOT_DIR / "services" / "ai-swarm" / "prompt_isolator.py")],
        "subsystem": "AI Swarm"
    },
    {
        "name": "Dynamic Bayesian Consensus Engine",
        "cmd": [sys.executable, str(ROOT_DIR / "services" / "ai-swarm" / "consensus.py")],
        "subsystem": "AI Swarm"
    },
    {
        "name": "Streaming Graph Edge Reducer",
        "cmd": [sys.executable, str(ROOT_DIR / "services" / "graph-engine" / "reducer.py")],
        "subsystem": "Graph Engine"
    },
    {
        "name": "Spectral Blast Radius (R_blast) Calculator",
        "cmd": [sys.executable, str(ROOT_DIR / "services" / "graph-engine" / "blast_radius.py")],
        "subsystem": "Graph Engine"
    },
    {
        "name": "Cold-Tier Graph Snapshot Archiver",
        "cmd": [sys.executable, str(ROOT_DIR / "services" / "graph-engine" / "archiver.py")],
        "subsystem": "Graph Engine"
    },
    {
        "name": "Adversarial Graph Perturbation Defense",
        "cmd": [sys.executable, str(ROOT_DIR / "services" / "graph-engine" / "perturbation_defense.py")],
        "subsystem": "Graph Engine"
    },
    {
        "name": "CT-HTGN Continuous-Time Temporal GNN Evaluator",
        "cmd": [sys.executable, str(ROOT_DIR / "services" / "ct-htgn-engine" / "evaluator.py")],
        "subsystem": "GNN Engine"
    },
    {
        "name": "Ghost-Mirror In-Kernel Deception & Canary Orchestrator",
        "cmd": [sys.executable, str(ROOT_DIR / "services" / "ghost-mirror" / "orchestrator.py")],
        "subsystem": "Ghost-Mirror"
    },
    {
        "name": "Red Team Drill: BPFDoor Passive Backdoor Emulation",
        "cmd": [sys.executable, str(ROOT_DIR / "tests" / "adversarial-ai" / "bpfdoor_emulation.py")],
        "subsystem": "Red Team"
    },
    {
        "name": "Red Team Drill: Ransomware Encryption & CoW Shunting",
        "cmd": [sys.executable, str(ROOT_DIR / "tests" / "adversarial-ai" / "ransomware_shunting.py")],
        "subsystem": "Red Team"
    },
    {
        "name": "High-Throughput Concurrency & Invariant Stress Fuzzer (25k Events)",
        "cmd": [sys.executable, str(ROOT_DIR / "tests" / "fuzzing" / "stress_fuzzer.py")],
        "subsystem": "Fuzzing & Robustness"
    },
    {
        "name": "LangGraph Tripartite Swarm (Forensic, RedTeam & Supervisor)",
        "cmd": [sys.executable, str(ROOT_DIR / "services" / "ai-swarm" / "langgraph_swarm.py")],
        "subsystem": "LangGraph Swarm"
    },
    {
        "name": "PyTorch Geometric RGCN Relational Classifier",
        "cmd": [sys.executable, str(ROOT_DIR / "services" / "ct-htgn-engine" / "rgcn_model.py")],
        "subsystem": "Graph ML"
    },
    {
        "name": "Ephemeral Docker Honeynet Sandbox Launcher",
        "cmd": [sys.executable, str(ROOT_DIR / "services" / "ghost-mirror" / "docker_sandbox.py")],
        "subsystem": "Ghost-Mirror Deception"
    },
    {
        "name": "Interactive Z3 SMT Studio Theorem Prover Engine",
        "cmd": [sys.executable, str(ROOT_DIR / "services" / "ai-swarm" / "smt_studio.py")],
        "subsystem": "Formal Methods"
    },
    {
        "name": "Forensic Evidence Vault & Cryptographic Chain of Custody",
        "cmd": [sys.executable, str(ROOT_DIR / "services" / "forensics" / "evidence_vault.py")],
        "subsystem": "Forensic Evidence"
    },
    {
        "name": "STIX 2.1 Threat Intelligence Bundle Exporter",
        "cmd": [sys.executable, str(ROOT_DIR / "services" / "ai-swarm" / "stix_exporter.py")],
        "subsystem": "Threat Intelligence"
    },
    {
        "name": "Enterprise Real-Time Kernel Telemetry Generator",
        "cmd": [sys.executable, str(ROOT_DIR / "services" / "telemetry-gen" / "live_kernel_stream.py")],
        "subsystem": "Telemetry Stream"
    },
]

def check_live_endpoints():
    endpoints = [
        ("Agency API Stats", "http://127.0.0.1:8500/api/stats"),
        ("Agency Workload Matrix", "http://127.0.0.1:8500/api/workload"),
        ("Gatekeeper Permissions", "http://127.0.0.1:8500/api/permissions"),
        ("SOC Provenance Graph", "http://127.0.0.1:8500/api/soc/provenance"),
        ("SOC 3D Console UI", "http://127.0.0.1:8500/soc"),
        ("SOC 2D React Flow UI", "http://127.0.0.1:8500/soc/flow"),
        ("SOC v2.0 Industrial UI", "http://127.0.0.1:8500/v2"),
    ]
    results = []
    for name, url in endpoints:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "AegisVerifier/1.0"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                status = resp.status
                results.append((name, status == 200, f"HTTP {status}"))
        except Exception as e:
            results.append((name, False, str(e)))
    return results

def main():
    print("=" * 80)
    print("  AEGISKERNEL: UNIFIED SUBSYSTEM VERIFICATION & HEALTH CERTIFICATION  ")
    print("=" * 80)
    print(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"Workspace: {ROOT_DIR}\n")

    passed = 0
    failed = 0
    start_total = time.perf_counter()

    for idx, test in enumerate(TEST_SUITES, 1):
        test_name = test["name"]
        cmd = test["cmd"]
        subsystem = test["subsystem"]

        print(f"[{idx:02d}/{len(TEST_SUITES):02d}] Testing [{subsystem}]: {test_name} ...", end=" ", flush=True)
        t0 = time.perf_counter()
        res = subprocess.run(cmd, capture_output=True, text=True)
        duration = (time.perf_counter() - t0) * 1000.0

        if res.returncode == 0:
            print(f"PASSED ({duration:.1f}ms)")
            passed += 1
        else:
            print(f"FAILED (code {res.returncode})")
            print(f"  STDERR: {res.stderr.strip()[:200]}")
            failed += 1

    print("\n--- Live Runtime Daemons & HTTP Health ---")
    endpoint_results = check_live_endpoints()
    for name, ok, detail in endpoint_results:
        print(f"  [Endpoint] {name:25s} -> {'ONLINE' if ok else 'OFFLINE'} ({detail})")
        if ok:
            passed += 1
        else:
            failed += 1

    total_tests = len(TEST_SUITES) + len(endpoint_results)
    total_duration = time.perf_counter() - start_total
    health_score = (passed / total_tests) * 100.0

    print("\n" + "=" * 80)
    print(f"  VERIFICATION COMPLETE: {passed}/{total_tests} Checks Passed ({health_score:.1f}% Health)")
    print(f"  Total Duration: {total_duration:.2f} seconds")
    print("=" * 80)

    if failed == 0:
        print("\n>>> ALL SYSTEM INVARIANTS MET. PRODUCTION READY CERTIFIED. <<<\n")
        return 0
    else:
        print(f"\n>>> WARNING: {failed} CHECKS FAILED. <<<\n")
        return 1

if __name__ == "__main__":
    sys.exit(main())
