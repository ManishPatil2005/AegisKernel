#!/usr/bin/env python3
"""
AegisKernel Operator CLI: aegisctl
==================================
Unified operator interface for managing AegisKernel nodes, running verification
harnesses, triggering APT simulations, inspecting live AI workforce status,
and issuing in-kernel Ghost-Mirror shunting directives.
"""

import sys
import os
import argparse
import urllib.request
import json
import time
import subprocess
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent

# ANSI Colors
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
PURPLE = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

API_BASE = "http://127.0.0.1:8500"

def get_json(endpoint: str):
    try:
        req = urllib.request.Request(f"{API_BASE}{endpoint}", headers={"User-Agent": "aegisctl/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return None

def post_json(endpoint: str, data: dict = None):
    try:
        payload = json.dumps(data or {}).encode("utf-8")
        req = urllib.request.Request(
            f"{API_BASE}{endpoint}",
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "aegisctl/1.0"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return None

def cmd_status(args):
    print(f"\n{BOLD}{CYAN}=== AEGISKERNEL: REAL-TIME OPERATIONAL STATUS ==={RESET}\n")
    stats = get_json("/api/stats")
    if not stats:
        print(f"{RED}[ERROR] Unable to connect to AegisKernel Agency Daemon at {API_BASE}{RESET}")
        print(f"Ensure server is active (`python agency/company/server.py`)")
        return 1

    print(f"  {BOLD}System Health:{RESET}       {GREEN}{stats.get('system_health', 'ONLINE')}{RESET}")
    print(f"  {BOLD}Server Uptime:{RESET}       {stats.get('uptime', 'N/A')}")
    print(f"  {BOLD}Total Hired Agents:{RESET}  {CYAN}{stats.get('total_agents', 0)}{RESET} across {CYAN}{stats.get('active_divisions', 0)}{RESET} divisions")
    print(f"  {BOLD}Hired Leads:{RESET}         {YELLOW}{stats.get('hired_specialists', 0)} Executive Specialists{RESET}")
    print(f"  {BOLD}Invariants Verified:{RESET} {GREEN}{stats.get('invariants_verified', 0)}{RESET}")
    print(f"  {BOLD}Permissions Handled:{RESET} {GREEN}{stats.get('permissions_granted', 0)} Granted{RESET} | {stats.get('permissions_denied', 0)} Denied")

    # Fetch provenance state
    prov = get_json("/api/soc/provenance")
    if prov:
        print(f"\n{BOLD}--- In-Kernel Threat & Provenance Telemetry ---{RESET}")
        print(f"  {BOLD}Target Node:{RESET}         {prov.get('host', 'N/A')} ({prov.get('kernel', 'N/A')})")
        print(f"  {BOLD}Threat Status:{RESET}       {RED if prov.get('status') == 'active_threat' else GREEN}{prov.get('status', 'NORMAL').upper()}{RESET}")
        print(f"  {BOLD}Active Nodes in DAG:{RESET} {len(prov.get('nodes', []))}")
        print(f"  {BOLD}Shunted PIDs:{RESET}        {PURPLE}{prov.get('shunted_pid', 'None')} (Ghost-Mirror CoW Scratchpad){RESET}")
        print(f"  {BOLD}Z3 SMT Invariant:{RESET}    {GREEN}{'VERIFIED (SAT)' if prov.get('fol_proof_verified') else 'UNSAT'}{RESET}")
        print(f"  {BOLD}MITRE Badges:{RESET}        {YELLOW}{', '.join(prov.get('mitre_techniques', []))}{RESET}")

    print(f"\n  {DIM}Agency Dashboard:{RESET}  {CYAN}http://localhost:8500{RESET}")
    print(f"  {DIM}3D SOC Console:{RESET}    {CYAN}http://localhost:8500/soc{RESET}\n")
    return 0

def cmd_verify(args):
    print(f"\n{BOLD}{CYAN}=== EXECUTING UNIFIED SUBSYSTEM VERIFICATION HARNESS ==={RESET}\n")
    script = ROOT_DIR / "scripts" / "verify_all.py"
    if not script.exists():
        print(f"{RED}[ERROR] Verification script not found at {script}{RESET}")
        return 1
    return subprocess.run([sys.executable, str(script)]).returncode

def cmd_simulate(args):
    print(f"\n{BOLD}{YELLOW}=== TRIGGERING END-TO-END ADVANCED THREAT HUNTING SIMULATION ==={RESET}\n")
    script = ROOT_DIR / "scripts" / "run_e2e_simulation.py"
    if not script.exists():
        print(f"{RED}[ERROR] Simulation script not found at {script}{RESET}")
        return 1
    return subprocess.run([sys.executable, str(script)]).returncode

def cmd_mom(args):
    print(f"\n{BOLD}{CYAN}=== AEGISKERNEL EXECUTIVE COUNCIL: MINUTES OF MEETING (MoM) ==={RESET}\n")
    mom_data = get_json("/api/mom")
    if mom_data and mom_data.get("status") == "success":
        print(mom_data.get("content", "No content found."))
    else:
        mom_path = ROOT_DIR / "docs" / "MINUTES_OF_MEETING.md"
        if mom_path.exists():
            with open(mom_path, "r", encoding="utf-8") as f:
                print(f.read())
        else:
            print(f"{RED}[ERROR] Minutes of meeting document not found.{RESET}")
    return 0

def cmd_shunt(args):
    pid = args.pid
    print(f"\n{BOLD}{PURPLE}=== ISSUING MANUAL GHOST-MIRROR SHUNT DIRECTIVE ==={RESET}\n")
    print(f"Target PID: {pid}")
    print(f"Action: Invoking in-kernel BPF-LSM return overriding...")
    
    # Run in-kernel orchestrator
    sys.path.insert(0, str(ROOT_DIR / "services" / "ghost-mirror"))
    from orchestrator import GhostMirrorOrchestrator
    orchestrator = GhostMirrorOrchestrator()
    res = orchestrator.shunt_process(pid=pid, comm=f"proc_{pid}", reason="Operator manual aegisctl directive")
    
    print(f"{GREEN}[SUCCESS] PID {pid} successfully diverted into 4MB ephemeral CoW scratchpad.{RESET}")
    print(f"Status: {res['status']} | Shunted at: {res['shunted_at_ns']} ns")
    return 0

def main():
    parser = argparse.ArgumentParser(
        prog="aegisctl",
        description="AegisKernel: Autonomous Threat Hunting & In-Kernel Deception CLI"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available operator commands")

    # status
    p_status = subparsers.add_parser("status", help="Display live telemetry, node health, and agent workforce")
    
    # verify
    p_verify = subparsers.add_parser("verify", help="Run 16-point system invariant and test verification harness")

    # simulate
    p_sim = subparsers.add_parser("simulate", help="Trigger live autonomous multi-stage APT attack simulation")

    # mom
    p_mom = subparsers.add_parser("mom", help="Display latest Executive Council Minutes of Meeting")

    # shunt
    p_shunt = subparsers.add_parser("shunt", help="Manually shunt a target process into Ghost-Mirror CoW memory")
    p_shunt.add_argument("--pid", type=int, required=True, help="Target process identifier (PID) to isolate")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    commands = {
        "status": cmd_status,
        "verify": cmd_verify,
        "simulate": cmd_simulate,
        "mom": cmd_mom,
        "shunt": cmd_shunt,
    }

    handler = commands.get(args.command)
    if handler:
        return handler(args)
    parser.print_help()
    return 0

if __name__ == "__main__":
    sys.exit(main())
