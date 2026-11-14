"""
AegisKernel: Unified Zero-Trust Security Runtime
=================================================
The central reference monitor decoupling AI model reasoning from execution authority:
1. Capability-Based Access Control (CBAC) with ephemeral TTL leases.
2. Canonical Path Whitelist Resolution (eliminates regex bypasses).
3. Deep Taint Tracking (prevents tainted data in privileged sinks).
4. Linux Landlock LSM & seccomp-BPF kernel sandboxing.
5. Append-only HMAC-SHA256 audit chaining.
"""

import functools
import inspect
from pathlib import Path
from typing import List, Optional, Callable, Dict, Any, Union

from .capability_engine import CapabilityEngine, CapabilityType, CapabilityUnauthorizedException
from .path_guard import CanonicalPathGuard, PathTraversalViolation
from .deep_taint import is_tainted, TaintedString
from .audit_ledger import CryptographicAuditLedger
from .kernel_sandbox import KernelSandboxEngine

class TaintViolationException(PermissionError):
    """Raised when tainted data attempts to reach a privileged sink."""
    pass

class AegisSecurityRuntime:
    """
    Unified security runtime instance managing CBAC, Taint, Path resolution,
    Audit ledgers, and Kernel sandboxing.
    """
    def __init__(
        self,
        allowed_workspaces: Optional[List[Union[str, Path]]] = None,
        audit_log_file: Optional[str] = None,
        master_secret: Optional[bytes] = None
    ):
        workspaces = allowed_workspaces or [Path.cwd()]
        self.path_guard = CanonicalPathGuard(workspaces)
        self.capability_engine = CapabilityEngine(signing_secret=master_secret)
        self.audit_ledger = CryptographicAuditLedger(master_key=master_secret, log_file=audit_log_file)
        self.kernel_sandbox = KernelSandboxEngine()

    def protect(
        self,
        required_capabilities: Optional[List[CapabilityType]] = None,
        path_param: Optional[str] = None,
        require_clean: bool = True,
        principal_id: str = "agent-worker-01"
    ):
        """
        Decorator enforcing zero-trust invariants on tool execution functions.
        """
        caps = required_capabilities or []

        def decorator(func: Callable):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                sig = inspect.signature(func)
                bound_args = sig.bind(*args, **kwargs)
                bound_args.apply_defaults()
                arg_dict = bound_args.arguments
                tool_name = func.__name__

                # 1. Capability Verification (CBAC)
                for cap in caps:
                    target_res = "*"
                    if path_param and path_param in arg_dict:
                        target_res = str(arg_dict[path_param])
                    
                    if not self.capability_engine.check_authorization(cap, target_res):
                        self.audit_ledger.append(
                            event_type="POLICY_DENY",
                            tool_name=tool_name,
                            principal_id=principal_id,
                            parameters=arg_dict,
                            verdict="BLOCKED",
                            details={"reason": f"Missing required capability lease: {cap.value}"}
                        )
                        raise CapabilityUnauthorizedException(
                            f"Access Denied: Principal '{principal_id}' lacks active capability lease for {cap.value}"
                        )

                # 2. Taint Tracking Sink Check
                if require_clean:
                    for param_name, param_val in arg_dict.items():
                        if is_tainted(param_val):
                            self.audit_ledger.append(
                                event_type="TAINT_VIOLATION",
                                tool_name=tool_name,
                                principal_id=principal_id,
                                parameters=arg_dict,
                                verdict="BLOCKED",
                                details={"tainted_parameter": param_name}
                            )
                            raise TaintViolationException(
                                f"Taint Sink Violation: Parameter '{param_name}' contains tainted data from external ingress."
                            )

                # 3. Path Validation & Canonical Resolution
                if path_param and path_param in arg_dict:
                    raw_path = arg_dict[path_param]
                    try:
                        resolved_path = self.path_guard.validate_and_resolve(raw_path)
                        # Replace argument with canonical path
                        bound_args.arguments[path_param] = str(resolved_path)
                    except PathTraversalViolation as ptv:
                        self.audit_ledger.append(
                            event_type="PATH_VIOLATION",
                            tool_name=tool_name,
                            principal_id=principal_id,
                            parameters=arg_dict,
                            verdict="BLOCKED",
                            details={"attempted_path": str(raw_path), "error": str(ptv)}
                        )
                        raise

                # 4. Kernel Sandbox Enforcement (Landlock restriction)
                if path_param and self.kernel_sandbox.landlock_supported:
                    allow_write = CapabilityType.FILE_WRITE in caps
                    self.kernel_sandbox.restrict_process_to_workspace(
                        self.path_guard.allowed_bases,
                        allow_write=allow_write
                    )

                # 5. Execute Tool Function
                try:
                    result = func(*bound_args.args, **bound_args.kwargs)
                    self.audit_ledger.append(
                        event_type="TOOL_EXECUTION",
                        tool_name=tool_name,
                        principal_id=principal_id,
                        parameters=arg_dict,
                        verdict="ALLOWED",
                        details={"status": "SUCCESS"}
                    )
                    return result
                except Exception as exc:
                    self.audit_ledger.append(
                        event_type="TOOL_ERROR",
                        tool_name=tool_name,
                        principal_id=principal_id,
                        parameters=arg_dict,
                        verdict="ERROR",
                        details={"error": str(exc)}
                    )
                    raise

            return wrapper
        return decorator

# Global default runtime instance
default_runtime = AegisSecurityRuntime()
aegis_protect = default_runtime.protect
grant_lease = default_runtime.capability_engine.grant_lease
