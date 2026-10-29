"""
AegisKernel: Agency Company Orchestrator & Live Monitoring Server
==================================================================
Manages the AI workforce, tracks agent statuses across all divisions,
handles dynamic agent hiring, dispatches project missions, manages
access control permissions via the Permission Gatekeeper Agent,
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

app = FastAPI(title="AegisKernel Agency Company Orchestrator", version="1.1.0")

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)

# In-memory company state
company_state = {
    "total_tasks_completed": 45,
    "active_missions": 6,
    "invariants_verified": 134,
    "permissions_granted": 18,
    "permissions_denied": 2,
    "start_time": time.time(),
}

# Live permission requests managed by the Permission Gatekeeper Agent
permission_requests: List[Dict[str, Any]] = [
    {
        "id": "PERM-01",
        "title": "Execute BPF-LSM Ghost-Mirror Process Shunt",
        "target": "PID 4096 (curl shellcode injection)",
        "requestor": "Deep Threat Hunting Agent",
        "division": "security",
        "risk_tier": "HIGH",
        "status": "PENDING",
        "timestamp": time.strftime("%H:%M:%S"),
        "fol_proof": "Reachable(Attacker, 4096) == SAT",
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
        "title": "Export Cold-Tier Provenance Parquet Snapshots to S3",
        "target": "s3://aegis-telemetry-archive/2026-10/",
        "requestor": "Causal Graph & GNN Architect",
        "division": "engineering",
        "risk_tier": "LOW",
        "status": "PENDING",
        "fol_proof": "Cryptographically Signed",
        "timestamp": time.strftime("%H:%M:%S"),
    },
]

# Live activity log stream
activity_logs: List[Dict[str, Any]] = [
    {
        "timestamp": time.strftime("%H:%M:%S"),
        "agent": "Permission Gatekeeper",
        "division": "security",
        "message": "Chief Permission & Access Gatekeeper assumed active command of Authorization Desk.",
        "status": "success",
    },
    {
        "timestamp": time.strftime("%H:%M:%S"),
        "agent": "eBPF Kernel Maintainer",
        "division": "security",
        "message": "Audited crates/aegis-ebpf/bpf/aegis_probes.bpf.c. In-kernel ring buffer and BPF-LSM hooks verified clean.",
        "status": "success",
    },
    {
        "timestamp": time.strftime("%H:%M:%S"),
        "agent": "Neuro-Symbolic Verifier",
        "division": "engineering",
        "message": "Executed Z3 SMT reachability proof for exploit path PID 100 -> 300. Invariant passed, Crown Jewels protected.",
        "status": "info",
    },
    {
        "timestamp": time.strftime("%H:%M:%S"),
        "agent": "Ghost-Mirror Deception Architect",
        "division": "security",
        "message": "Configured copy-on-write memory shunting map aegis_ghost_shunt_map with 16,384 entry capacity.",
        "status": "warning",
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
    
    # Priority AegisKernel hired specialists
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
        "system_health": "100.0% OPERATIONAL",
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
    """Server-Sent Events streaming live simulation ticks."""
    async def event_generator():
        simulated_actions = [
            ("Permission Gatekeeper", "security", "Evaluating Dual-Authorization Quorum for containment ticket: Invariant VALID -> Decision: ACCESS GRANTED (YES).", "success"),
            ("eBPF Kernel Maintainer", "security", "Executing CO-RE verifier pass against Linux 6.6 tracepoints.", "success"),
            ("Neuro-Symbolic Verifier", "engineering", "Validating Z3 reachability theorem: SMT solver returned SAT in 4.2ms.", "info"),
            ("Ghost-Mirror Deception Architect", "security", "Synthesizing dynamic canary tokens in virtual filesystem nodes.", "warning"),
            ("SOC WebGL Canvas Architect", "engineering", "Optimizing Three.js instanced mesh rendering for 50k nodes at 60 FPS.", "info"),
            ("Adversarial Rootkit Operator", "security", "Injecting synthetic raw socket frame to benchmark BPFDoor passive detection.", "warning"),
            ("Causal Graph & GNN Architect", "engineering", "Updating continuous exponential time decay memory vectors (Delta t).", "success"),
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
            await asyncio.sleep(3.0)

    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        with open(index_file, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>AegisKernel Agency Dashboard Initializing...</h1>"

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8500, log_level="info")
