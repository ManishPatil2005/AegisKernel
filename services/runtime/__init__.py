"""
AegisKernel: Zero-Trust Security Runtime for Autonomous AI Agents
"""

from .capability_engine import CapabilityEngine, CapabilityType, CapabilityToken, CapabilityUnauthorizedException
from .path_guard import CanonicalPathGuard, PathTraversalViolation
from .deep_taint import TaintedString, AegisJSONEncoder, AegisJSONDecoder, is_tainted, sanitize_taint
from .audit_ledger import CryptographicAuditLedger, AuditRecord
from .kernel_sandbox import KernelSandboxEngine
from .runtime import AegisSecurityRuntime, TaintViolationException, default_runtime, aegis_protect, grant_lease

__all__ = [
    "CapabilityEngine",
    "CapabilityType",
    "CapabilityToken",
    "CapabilityUnauthorizedException",
    "CanonicalPathGuard",
    "PathTraversalViolation",
    "TaintedString",
    "AegisJSONEncoder",
    "AegisJSONDecoder",
    "is_tainted",
    "sanitize_taint",
    "CryptographicAuditLedger",
    "AuditRecord",
    "KernelSandboxEngine",
    "AegisSecurityRuntime",
    "TaintViolationException",
    "default_runtime",
    "aegis_protect",
    "grant_lease"
]
