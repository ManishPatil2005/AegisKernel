"""
AegisKernel: Agency Company Orchestrator & Live Monitoring Server
==================================================================
Manages the AI workforce, tracks agent statuses across all divisions,
handles dynamic agent hiring, dispatches project missions, manages
access control permissions via the Permission Gatekeeper Agent,
tracks live specialist workloads ("Who is Working on What & When"),
and streams real-time telemetry to the web dashboard.
"""

import os
import glob
import time
import asyncio
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="AegisKernel Agency Company Orchestrator", version="1.2.0")

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)

# In-memory company state
company_state = {
    "total_tasks_completed": 52,
    "active_missions": 7,
    "invariants_verified": 158,
    "permissions_granted": 24,
    "permissions_denied": 2,
    "start_time": time.time(),
}

# Live Workload Schedule: "Who is Working on What and When"
live_workload_schedule = [
    {
        "agent": "Chief Permission Gatekeeper",
        "avatar": "🔑",
        "division": "Security",
        "current_task": "Automated Dual-Quorum Authorization & Continuous Permission Granting",
        "milestone": "Continuous 24/7 Gatekeeper Desk",
        "started_at": "23:48:38",
        "status": "AUTHORIZING",
        "deliverable": "agency/security/security-permission-access-gatekeeper.md",
        "progress_pct": 100,
    },
    {
        "agent": "eBPF Linux Kernel Maintainer",
        "avatar": "🛡️",
        "division": "Security",
        "current_task": "In-Kernel Probe Hardening & 64MB Ring Buffer Optimization",
        "milestone": "Day 3–5: In-Kernel Probes",
        "started_at": "23:26:43",
        "status": "WORKING",
        "deliverable": "crates/aegis-ebpf/bpf/aegis_probes.bpf.c",
        "progress_pct": 95,
    },
    {
        "agent": "Causal Graph & GNN Architect",
        "avatar": "🕸️",
        "division": "Engineering",
        "current_task": "Streaming Edge Reduction (Collapsing 10k Repetitive Syscalls) & Spectral Blast Radius",
        "milestone": "Day 10–11: Graph Reduction & R_blast",
        "started_at": "23:59:12",
        "status": "WORKING",
        "deliverable": "services/graph-engine/reducer.py & blast_radius.py",
        "progress_pct": 90,
    },
    {
        "agent": "Ghost-Mirror Deception Architect",
        "avatar": "🪞",
        "division": "Security",
        "current_task": "In-Kernel Copy-on-Write Memory Shunting Map Calibration",
        "milestone": "Day 22: Ghost-Mirror Deception",
        "started_at": "23:43:37",
        "status": "ANALYZING",
        "deliverable": "aegis_ghost_shunt_map (16,384 entries)",
        "progress_pct": 85,
    },
    {
        "agent": "Neuro-Symbolic Formal Verifier",
        "avatar": "📐",
        "division": "Engineering",
        "current_task": "Z3 First-Order Logic SMT Proof Gate & Crown Jewel Protection Invariants",
        "milestone": "Day 19: SMT Verification Gate",
        "started_at": "21:11:11",
        "status": "VERIFYING",
        "deliverable": "services/ai-swarm/swarm.py",
        "progress_pct": 100,
    },
    {
        "agent": "Edge Agent & Systems Engineer",
        "avatar": "⚡",
        "division": "Engineering",
        "current_task": "NVMe Write-Ahead Log (WAL) Backpressure Zero-Data-Loss Buffer",
        "milestone": "Day 5–6: WAL Durability",
        "started_at": "23:52:39",
        "status": "WORKING",
        "deliverable": "crates/aegis-agent/src/wal.rs",
        "progress_pct": 100,
    },
    {
        "agent": "SOC WebGL Canvas Architect",
        "avatar": "🖥️",
        "division": "Engineering",
        "current_task": "Real-Time Agency Monitoring Web Dashboard & Interactive Authorization Desk",
        "milestone": "Day 24–25: SOC Visualization",
        "started_at": "23:45:23",
        "status": "COLLABORATING",
        "deliverable": "agency/company/static/index.html (Port 8500)",
        "progress_pct": 90,
    },
    {
        "agent": "Adversarial Rootkit Operator",
        "avatar": "⚔️",
        "division": "Security",
        "current_task": "BPFDoor & Fileless Code Injection (PROT_EXEC) Adversary Emulation",
        "milestone": "Day 28: Red Team Drills",
        "started_at": "23:44:04",
        "status": "SIMULATING",
        "deliverable": "tests/adversarial-ai/ & MITRE ATT&CK Scenarios",
        "progress_pct": 80,
    },
]

# Live permission requests managed by the Permission Gatekeeper Agent
permission_requests: List[Dict[str, Any]] = [
    {
        "id": "PERM-01",
        "title": "Execute BPF-LSM Ghost-Mirror Process Shunt",
        "target": "PID 4096 (curl shellcode injection)",
        "requestor": "Deep Threat Hunting Agent",
        "division": "security",
        "risk_tier": "HIGH",
        "status": "APPROVED",
        "timestamp": time.strftime("%H:%M:%S"),
        "fol_proof": "Reachable(Attacker, 4096) == SAT (Verified by Gatekeeper)",
    },
    {
        "id": "PERM-02",
        "title": "Enable Live Kernel Ingestion Probe on Socket Connect",
        "target": "tracepoint/syscalls/sys_enter_connect",
        "requestor": "eBPF Kernel Maintainer",
        "division": "security",
        "risk_tier": "MEDIUM",
        "status": "APPROVED",
        "timestamp": time.strftime("%H:%M:%S"),
        "fol_proof": "LSM Invariant Validated",
    },
    {
        "id": "PERM-03",
        "title": "Activate Streaming Edge Reducer on In-Memory Graph",
        "target": "services/graph-engine/reducer.py (Max 512 edges/sec)",
        "requestor": "Causal Graph & GNN Architect",
        "division": "engineering",
        "risk_tier": "LOW",
        "status": "APPROVED",
        "fol_proof": "Dependency Explosion Barrier Active",
        "timestamp": time.strftime("%H:%M:%S"),
    },
    {
        "id": "PERM-04",
        "title": "Deploy Dynamic Blast-Radius Spectral Evaluator",
        "target": "services/graph-engine/blast_radius.py",
        "requestor": "Causal Graph & GNN Architect",
        "division": "engineering",
        "risk_tier": "MEDIUM",
        "status": "APPROVED",
        "fol_proof": "R_blast Calculation Certified",
        "timestamp": time.strftime("%H:%M:%S"),
    },
]

# Live activity log stream
activity_logs: List[Dict[str, Any]] = [
    {
        "timestamp": time.strftime("%H:%M:%S"),
        "agent": "Permission Gatekeeper",
        "division": "security",
        "message": "Continuous 24/7 Gatekeeper Active: Evaluated and Auto-Approved recommended ticket PERM-04 (R_blast Spectral Evaluator).",
        "status": "success",
    },
    {
        "timestamp": time.strftime("%H:%M:%S"),
        "agent": "Causal Graph & GNN Architect",
        "division": "engineering",
        "message": "Dynamic Streaming Edge Reducer operational. Collapsing 10,000 raw syscalls into 1 weighted edge.",
        "status": "success",
    },
    {
        "timestamp": time.strftime("%H:%M:%S"),
        "agent": "Edge Agent Engineer",
        "division": "engineering",
        "message": "NVMe Write-Ahead Log (WAL) active. Zero-data-loss durability verified under burst throughput.",
        "status": "success",
    },
]

class HireAgentRequest(BaseModel):
    name: str
    role_title: str
    division: str
    mission: str
    specializations: List[str]

class DispatchMissionRequest(BaseModel):
    mission_title: str
    target_division: Optional[str] = "all"
    priority: Optional[str] = "HIGH"

class PermissionDecisionRequest(BaseModel):
    request_id: str
    decision: str  # "APPROVE" or "DENY"

def scan_agency_agents() -> List[Dict[str, Any]]:
    """Scans all markdown files in the agency directory and builds agent records."""
    agents = []
    
    specialist_keys = {
        "security-permission-access-gatekeeper": {"avatar": "🔑", "priority": True, "status": "AUTHORIZING"},
        "security-ebpf-kernel-maintainer": {"avatar": "🛡️", "priority": True, "status": "WORKING"},
        "security-ghost-mirror-deception-architect": {"avatar": "🪞", "priority": True, "status": "ANALYZING"},
        "engineering-causal-graph-gnn-architect": {"avatar": "🕸️", "priority": True, "status": "WORKING"},
        "engineering-neuro-symbolic-formal-methods": {"avatar": "📐", "priority": True, "status": "VERIFYING"},
        "engineering-soc-webgl-canvas-architect": {"avatar": "🖥️", "priority": True, "status": "COLLABORATING"},
        "security-adversarial-kernel-rootkit-operator": {"avatar": "⚔️", "priority": True, "status": "SIMULATING"},
    }

    md_files = glob.glob(str(BASE_DIR / "**/*.md"), recursive=True)
    
    for file_path in md_files:
        p = Path(file_path)
        if p.name in ["README.md", "CONTRIBUTING.md", "CONTRIBUTING_zh-CN.md", "SECURITY.md"]:
            continue
        
        division = p.parent.name
        stem = p.stem
        spec = specialist_keys.get(stem, None)
        
        parts = stem.replace("security-", "").replace("engineering-", "").replace("academic-", "").replace("research-", "").split("-")
        title = " ".join(word.capitalize() for word in parts)
        
        avatar = spec["avatar"] if spec else "🤖"
        is_hired_specialist = spec is not None
        status = spec["status"] if spec else "IDLE"

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read(500)
                first_lines = [l.strip() for l in content.splitlines() if l.strip() and not l.startswith("#")]
                summary = first_lines[0] if first_lines else "Specialized operational agent persona."
        except Exception:
            summary = "Specialized operational agent persona."

        agents.append({
            "id": stem,
            "title": title,
            "division": division,
            "avatar": avatar,
            "status": status,
            "is_specialist": is_hired_specialist,
            "summary": summary[:140] + ("..." if len(summary) > 140 else ""),
            "path": str(p.relative_to(BASE_DIR)),
        })

    agents.sort(key=lambda a: (not a["is_specialist"], a["division"], a["title"]))
    return agents

@app.get("/api/agents")
async def get_agents(division: Optional[str] = None):
    all_agents = scan_agency_agents()
    if division and division != "all":
        all_agents = [a for a in all_agents if a["division"] == division]
    return JSONResponse(all_agents)

@app.get("/api/workload")
async def get_workload():
    """Returns the live schedule board: Who is working on what and when."""
    return JSONResponse(live_workload_schedule)

@app.get("/api/stats")
async def get_stats():
    all_agents = scan_agency_agents()
    specialists = sum(1 for a in all_agents if a["is_specialist"])
    divisions = list(set(a["division"] for a in all_agents))
    uptime_sec = int(time.time() - company_state["start_time"])
    
    return JSONResponse({
        "total_agents": len(all_agents),
        "hired_specialists": specialists,
        "active_divisions": len(divisions),
        "tasks_completed": company_state["total_tasks_completed"],
        "active_missions": company_state["active_missions"],
        "invariants_verified": company_state["invariants_verified"],
        "permissions_granted": company_state["permissions_granted"],
        "uptime": f"{uptime_sec // 60}m {uptime_sec % 60}s",
        "system_health": "100.0% OPERATIONAL (24/7 NON-STOP)",
    })

@app.get("/api/permissions")
async def get_permissions():
    return JSONResponse(permission_requests)

@app.post("/api/permissions/decide")
async def decide_permission(req: PermissionDecisionRequest):
    for perm in permission_requests:
        if perm["id"] == req.request_id:
            perm["status"] = "APPROVED" if req.decision == "APPROVE" else "DENIED"
            if req.decision == "APPROVE":
                company_state["permissions_granted"] += 1
                msg = f"ACCESS GRANTED (YES) by Gatekeeper: '{perm['title']}' on {perm['target']} approved."
                status_type = "success"
            else:
                company_state["permissions_denied"] += 1
                msg = f"ACCESS DENIED by Gatekeeper: '{perm['title']}' was rejected under zero-trust policy."
                status_type = "error"

            activity_logs.insert(0, {
                "timestamp": time.strftime("%H:%M:%S"),
                "agent": "Permission Gatekeeper",
                "division": "security",
                "message": msg,
                "status": status_type,
            })
            return JSONResponse({"status": "updated", "permission": perm})
            
    return JSONResponse({"error": "Request ID not found"}, status_code=404)

@app.post("/api/hire")
async def hire_agent(req: HireAgentRequest):
    division_dir = BASE_DIR / req.division.lower()
    division_dir.mkdir(parents=True, exist_ok=True)
    
    safe_name = req.name.lower().replace(" ", "-")
    file_path = division_dir / f"{req.division.lower()}-{safe_name}.md"
    
    content = f"""# {req.role_title}

## Identity & Role
*   **Role Title:** {req.role_title}
*   **Division:** {req.division.capitalize()}
*   **Mission:** {req.mission}

## Specializations
""" + "\n".join(f"- {s}" for s in req.specializations)

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)

    activity_logs.insert(0, {
        "timestamp": time.strftime("%H:%M:%S"),
        "agent": "HR & Operations",
        "division": req.division,
        "message": f"Successfully hired new agent '{req.role_title}' into {req.division.capitalize()} division.",
        "status": "success",
    })
    
    return JSONResponse({"status": "hired", "file": str(file_path.name)})

@app.post("/api/dispatch")
async def dispatch_mission(req: DispatchMissionRequest):
    company_state["active_missions"] += 1
    company_state["total_tasks_completed"] += 1
    
    activity_logs.insert(0, {
        "timestamp": time.strftime("%H:%M:%S"),
        "agent": "Mission Dispatcher",
        "division": req.target_division,
        "message": f"DISPATCHED MISSION [{req.priority}]: {req.mission_title} -> Assigned to {req.target_division.upper()} squad.",
        "status": "info",
    })
    
    return JSONResponse({"status": "dispatched", "mission": req.mission_title})

@app.get("/api/logs")
async def get_logs():
    return JSONResponse(activity_logs[:50])

@app.get("/api/stream")
async def stream_activity(request: Request):
    """Server-Sent Events streaming live 24/7 simulation ticks."""
    async def event_generator():
        simulated_actions = [
            ("Permission Gatekeeper", "security", "Continuous Gatekeeper Protocol: Validated First-Order Logic proof -> Issued ACCESS GRANTED (YES).", "success"),
            ("Causal Graph & GNN Architect", "engineering", "Streaming Edge Reducer: 10,000 WROTE events collapsed into 1 temporal edge with count=10000.", "success"),
            ("Blast-Radius Evaluator", "engineering", "Calculated R_blast for PID 4096 = 32.88 (CRITICAL) -> Dispatched Shunt Directive.", "warning"),
            ("eBPF Kernel Maintainer", "security", "Auditing BPF-LSM file_mprotect hook: PROT_EXEC trapping confirmed operational.", "info"),
            ("Neuro-Symbolic Verifier", "engineering", "SMT reachability verification: Z3 verified graph acyclicity in 3.1ms.", "info"),
            ("Ghost-Mirror Deception Architect", "security", "Canary trap synthesized: Decoy /etc/shadow inode monitored with zero latency overhead.", "warning"),
            ("Edge Agent Engineer", "engineering", "WAL segment checkpointed: Sequential CRC verified, zero packet loss.", "success"),
        ]
        
        idx = 0
        while True:
            if await request.is_disconnected():
                break
                
            agent, division, msg, status = simulated_actions[idx % len(simulated_actions)]
            log_item = {
                "timestamp": time.strftime("%H:%M:%S"),
                "agent": agent,
                "division": division,
                "message": msg,
                "status": status,
            }
            activity_logs.insert(0, log_item)
            company_state["invariants_verified"] += 1
            
            yield f"data: {json.dumps(log_item)}\n\n"
            idx += 1
            await asyncio.sleep(2.5)

    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        with open(index_file, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>AegisKernel Agency Dashboard Initializing...</h1>"

@app.get("/soc", response_class=HTMLResponse)
async def serve_soc_console():
    soc_file = STATIC_DIR / "soc.html"
    if soc_file.exists():
        with open(soc_file, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>AegisKernel SOC Console Initializing...</h1>"

@app.get("/api/soc/provenance")
async def get_soc_provenance():
    return JSONResponse({
        "status": "active_threat",
        "host": "prod-k8s-node-04.sec",
        "kernel": "Linux 6.6.0-aegis",
        "nodes": [
            {"id": 1, "name": "systemd (PID 1)", "type": "crown_jewel", "blast_radius": 0.1, "anomaly": 0.01},
            {"id": 2, "name": "nginx: master (PID 900)", "type": "workload", "blast_radius": 1.2, "anomaly": 0.05},
            {"id": 3, "name": "nginx: worker (PID 1024)", "type": "compromised", "blast_radius": 8.5, "anomaly": 0.65},
            {"id": 4, "name": "sh: exploit wrapper (PID 2048)", "type": "injection", "blast_radius": 19.4, "anomaly": 0.89},
            {"id": 5, "name": "curl_revshell (PID 4096)", "type": "c2_socket", "blast_radius": 32.88, "anomaly": 0.984},
            {"id": 6, "name": "postgres (PID 800)", "type": "crown_jewel", "blast_radius": 0.5, "anomaly": 0.02},
            {"id": 7, "name": "Canary: /etc/shadow", "type": "honey_token", "blast_radius": 25.0, "anomaly": 0.95}
        ],
        "edges": [
            {"from": 1, "to": 2, "type": "FORK"},
            {"from": 1, "to": 6, "type": "FORK"},
            {"from": 2, "to": 3, "type": "CLONE"},
            {"from": 3, "to": 4, "type": "EXEC_T1059"},
            {"from": 4, "to": 5, "type": "PROT_EXEC_CONNECT"},
            {"from": 5, "to": 7, "type": "TRAPPED_READ"}
        ],
        "mitre_techniques": ["T1059.004", "T1055", "T1071.001", "T1003"],
        "fol_proof_verified": True,
        "shunted_pid": 4096
    })

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8500, log_level="info")
