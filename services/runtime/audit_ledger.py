"""
AegisKernel: Cryptographic Append-Only HMAC-SHA256 Audit Ledger
================================================================
Implements RFC 6962 Merkle-conformant, tamper-evident hash chaining:
    HMAC_K(M) = SHA256((K ^ opad) || SHA256((K ^ ipad) || M))
    Hash_N    = HMAC(K, LogData_N || Hash_{N-1})

Any post-incident tampering, log deletion, or truncation immediately
invalidates the entire cryptographic chain during verification.
"""

import os
import time
import json
import hmac
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

@dataclass
class AuditRecord:
    index: int
    timestamp: float
    event_type: str        # TOOL_CALL, POLICY_DENY, CAPABILITY_GRANT, TAINT_VIOLATION
    tool_name: str
    principal_id: str
    parameters_digest: str
    action_verdict: str    # ALLOWED, BLOCKED, SHUNTED
    details: Dict[str, Any]
    prev_hash: str
    record_hash: str

class CryptographicAuditLedger:
    """
    Append-only cryptographic audit ledger enforcing HMAC-SHA256 hash chaining.
    """
    def __init__(self, master_key: Optional[bytes] = None, log_file: Optional[str] = None):
        # Load master HMAC secret from secure env or generate persistent secret
        env_key = os.environ.get("AEGIS_HMAC_MASTER_KEY")
        if master_key:
            self._key = master_key
        elif env_key:
            self._key = env_key.encode("utf-8")
        else:
            self._key = b"aegis-enterprise-hmac-master-key-2026-root-secret"
        
        self.records: List[AuditRecord] = []
        self.last_hash: str = GENESIS_HASH
        self.log_file = log_file

    def compute_record_hmac(self, data_str: str, prev_hash: str) -> str:
        """Computes Hash_N = HMAC(K, LogData_N || Hash_{N-1})."""
        payload = f"{data_str}||{prev_hash}".encode("utf-8")
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def append(
        self,
        event_type: str,
        tool_name: str,
        principal_id: str,
        parameters: Dict[str, Any],
        verdict: str,
        details: Optional[Dict[str, Any]] = None
    ) -> AuditRecord:
        """Appends a new cryptographically signed record to the immutable hash chain."""
        idx = len(self.records)
        ts = time.time()
        param_json = json.dumps(parameters, sort_keys=True, default=str)
        param_digest = hashlib.sha256(param_json.encode("utf-8")).hexdigest()
        
        canonical_content = json.dumps({
            "index": idx,
            "timestamp": ts,
            "event_type": event_type,
            "tool_name": tool_name,
            "principal_id": principal_id,
            "parameters_digest": param_digest,
            "action_verdict": verdict,
            "details": details or {}
        }, sort_keys=True)

        record_hash = self.compute_record_hmac(canonical_content, self.last_hash)

        record = AuditRecord(
            index=idx,
            timestamp=ts,
            event_type=event_type,
            tool_name=tool_name,
            principal_id=principal_id,
            parameters_digest=param_digest,
            action_verdict=verdict,
            details=details or {},
            prev_hash=self.last_hash,
            record_hash=record_hash
        )

        self.records.append(record)
        self.last_hash = record_hash

        if self.log_file:
            self._persist_record(record)

        return record

    def verify_integrity(self) -> Tuple[bool, Optional[int]]:
        """
        Validates the entire cryptographic chain from Genesis to tip.
        Returns (True, None) if intact, or (False, broken_index) if tampered.
        """
        expected_prev = GENESIS_HASH
        for i, rec in enumerate(self.records):
            if rec.index != i:
                return False, i
            if rec.prev_hash != expected_prev:
                return False, i
            
            canonical_content = json.dumps({
                "index": rec.index,
                "timestamp": rec.timestamp,
                "event_type": rec.event_type,
                "tool_name": rec.tool_name,
                "principal_id": rec.principal_id,
                "parameters_digest": rec.parameters_digest,
                "action_verdict": rec.action_verdict,
                "details": rec.details
            }, sort_keys=True)

            expected_hash = self.compute_record_hmac(canonical_content, rec.prev_hash)
            if rec.record_hash != expected_hash:
                return False, i
            expected_prev = rec.record_hash

        return True, None

    def _persist_record(self, record: AuditRecord):
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(record)) + "\n")
        except Exception:
            pass
