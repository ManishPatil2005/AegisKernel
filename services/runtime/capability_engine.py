"""
AegisKernel: Capability-Based Access Control (CBAC) Engine
==========================================================
Eliminates static, ambient permissions by enforcing fine-grained,
unforgeable, ephemeral capability leases:
- Default-deny architecture (zero ambient permissions).
- Cryptographically signed tokens with expiration TTLs.
- Dynamic leasing context managers:
    with engine.grant_lease(CapabilityType.NETWORK_OUTBOUND, ttl_seconds=15, resource="api.stripe.com"):
        agent.execute_payment_tool()
"""

import os
import time
import uuid
import hmac
import hashlib
from enum import Enum, auto
from dataclasses import dataclass
from typing import Optional, Set, Dict, Any, List
from contextlib import contextmanager

class CapabilityType(Enum):
    FILE_READ = "FILE_READ"
    FILE_WRITE = "FILE_WRITE"
    SHELL_EXEC = "SHELL_EXEC"
    NETWORK_OUTBOUND = "NETWORK_OUTBOUND"
    DATABASE_MODIFY = "DATABASE_MODIFY"
    ENVIRONMENT_ACCESS = "ENVIRONMENT_ACCESS"

class CapabilityUnauthorizedException(PermissionError):
    """Raised when an agent attempts an action without a valid capability lease."""
    pass

@dataclass(frozen=True)
class CapabilityToken:
    token_id: str
    capability: CapabilityType
    resource_pattern: str   # Glob or hostname/CIDR
    granted_at: float
    ttl_seconds: float
    signature: str

    def is_expired(self) -> bool:
        return time.time() > (self.granted_at + self.ttl_seconds)

    def is_resource_authorized(self, target_resource: str) -> bool:
        if self.resource_pattern == "*" or self.resource_pattern == target_resource:
            return True
        # Prefix matching
        if self.resource_pattern.endswith("*") and target_resource.startswith(self.resource_pattern[:-1]):
            return True
        return False

class CapabilityEngine:
    """
    Manages generation, signing, leasing, and verification of ephemeral capability tokens.
    """
    def __init__(self, signing_secret: Optional[bytes] = None):
        self._secret = signing_secret or os.environ.get("AEGIS_CBAC_KEY", "cbac-root-secret-key-2026").encode("utf-8")
        # Thread/context-local active lease stack
        self._active_leases: Dict[CapabilityType, List[CapabilityToken]] = {
            cap: [] for cap in CapabilityType
        }

    def _sign_token(self, token_id: str, cap: CapabilityType, resource: str, granted_at: float, ttl: float) -> str:
        payload = f"{token_id}|{cap.value}|{resource}|{granted_at}|{ttl}".encode("utf-8")
        return hmac.new(self._secret, payload, hashlib.sha256).hexdigest()

    def issue_token(self, capability: CapabilityType, ttl_seconds: float = 30.0, resource_pattern: str = "*") -> CapabilityToken:
        """Issues an unforgeable cryptographically signed capability token."""
        t_id = str(uuid.uuid4())
        now = time.time()
        sig = self._sign_token(t_id, capability, resource_pattern, now, ttl_seconds)
        return CapabilityToken(
            token_id=t_id,
            capability=capability,
            resource_pattern=resource_pattern,
            granted_at=now,
            ttl_seconds=ttl_seconds,
            signature=sig
        )

    def verify_token(self, token: CapabilityToken) -> bool:
        """Verifies signature authenticity and expiration."""
        expected_sig = self._sign_token(
            token.token_id,
            token.capability,
            token.resource_pattern,
            token.granted_at,
            token.ttl_seconds
        )
        if not hmac.compare_digest(token.signature, expected_sig):
            return False
        if token.is_expired():
            return False
        return True

    def check_authorization(self, capability: CapabilityType, target_resource: str = "*") -> bool:
        """
        Validates if an active, unexpired lease exists for the requested capability
        and resource scope.
        """
        active_list = self._active_leases.get(capability, [])
        valid_leases = []
        authorized = False

        for tok in active_list:
            if self.verify_token(tok) and tok.is_resource_authorized(target_resource):
                authorized = True
                valid_leases.append(tok)
            elif not tok.is_expired():
                valid_leases.append(tok)

        # Prune expired tokens
        self._active_leases[capability] = valid_leases
        return authorized

    @contextmanager
    def grant_lease(self, capability: CapabilityType, ttl_seconds: float = 30.0, resource_pattern: str = "*"):
        """
        Context manager providing ephemeral capability leases with automatic revocation on exit.
        """
        token = self.issue_token(capability, ttl_seconds, resource_pattern)
        self._active_leases[capability].append(token)
        try:
            yield token
        finally:
            if token in self._active_leases[capability]:
                self._active_leases[capability].remove(token)
