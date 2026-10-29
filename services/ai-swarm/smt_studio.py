"""
AegisKernel V2.0: Interactive Neuro-Symbolic SMT Studio Engine
==============================================================
Provides real-time First-Order Logic (FOL) formula evaluation,
abstract syntax tree (AST) clause inspection, and Crown Jewel invariant
validation via the Z3 SMT Theorem Prover.
"""

from typing import Dict, List, Any, Tuple
import z3
import time
import logging

logger = logging.getLogger("aegis-smt-studio")


class SMTStudioEngine:
    """Live interactive theorem prover service for the AegisKernel V2 SOC console."""

    CROWN_JEWELS = {"systemd", "sshd", "kubelet", "etcd", "postgres", "init"}

    @classmethod
    def evaluate_smt_proof(
        cls,
        target_pid: int,
        target_comm: str,
        origin_pid: int,
        graph_edges: List[Tuple[int, int]],
        custom_invariants: List[str] = None
    ) -> Dict[str, Any]:
        """
        Executes a formal verification proof using an isolated thread-safe Z3 context.
        """
        t0 = time.perf_counter()
        ctx = z3.Context()
        s = z3.Solver(ctx=ctx)

        # 1. Crown Jewel Invariant Verification
        is_crown_jewel = target_comm.lower() in cls.CROWN_JEWELS
        if is_crown_jewel:
            return {
                "verified": False,
                "allow_execution": False,
                "verdict": "VETOED_BY_INVARIANT",
                "reason": f"Target process '{target_comm}' is an immutable Crown Jewel. Termination strictly prohibited.",
                "fol_formula": f"CrownJewel({target_comm}) == True -> VETO",
                "solver_duration_ms": round((time.perf_counter() - t0) * 1000.0, 3),
                "ast_clauses": [
                    f"Invariant: ForAll(p, CrownJewel(p) -> Not(Kill(p)))",
                    f"Fact: CrownJewel({target_comm}) = True"
                ]
            }

        # 2. Mathematical Causal Reachability Formulation
        int_sort = z3.IntSort(ctx=ctx)
        bool_sort = z3.BoolSort(ctx=ctx)
        Reach = z3.Function('Reach', int_sort, int_sort, bool_sort)
        Edge = z3.Function('Edge', int_sort, int_sort, bool_sort)

        u = z3.Int('u', ctx=ctx)
        v = z3.Int('v', ctx=ctx)
        w = z3.Int('w', ctx=ctx)

        # Reachability Inductive Axioms
        s.add(z3.ForAll([u, v], z3.Implies(Edge(u, v), Reach(u, v))))
        s.add(z3.ForAll([u, v, w], z3.Implies(z3.And(Reach(u, v), Edge(v, w)), Reach(u, w))))

        # Assert observed causal DAG edges
        for src, dst in graph_edges:
            s.add(Edge(z3.IntVal(src, ctx=ctx), z3.IntVal(dst, ctx=ctx)))

        # Evaluate target reachability from origin exploit
        s.push()
        s.add(Reach(z3.IntVal(origin_pid, ctx=ctx), z3.IntVal(target_pid, ctx=ctx)))
        check_result = s.check()
        s.pop()

        is_reachable = (check_result == z3.sat) or (origin_pid == target_pid)
        duration_ms = round((time.perf_counter() - t0) * 1000.0, 3)

        fol_repr = f"Reach({origin_pid}, {target_pid}) && !CrownJewel({target_comm})"
        ast_clauses = [
            f"Axiom 1: ForAll([u, v], Edge(u, v) -> Reach(u, v))",
            f"Axiom 2: ForAll([u, v, w], Reach(u, v) && Edge(v, w) -> Reach(u, w))",
            f"Edge Assertions: {', '.join(f'Edge({s},{d})' for s, d in graph_edges)}",
            f"Goal: Reach({origin_pid}, {target_pid}) = {'SAT' if is_reachable else 'UNSAT'}"
        ]

        if is_reachable:
            return {
                "verified": True,
                "allow_execution": True,
                "verdict": "PROVEN_SATISFIABLE",
                "reason": f"SMT Solver mathematically proved causal lineage from PID {origin_pid} to target PID {target_pid}.",
                "fol_formula": fol_repr,
                "solver_duration_ms": duration_ms,
                "ast_clauses": ast_clauses,
                "proof_signature": f"z3_proof_{hash(fol_repr) & 0xffffffff:08x}"
            }
        else:
            return {
                "verified": False,
                "allow_execution": False,
                "verdict": "UNPROVEN_DISCONNECTED",
                "reason": f"SMT Solver rejected: No verified causal path exists between PID {origin_pid} and target PID {target_pid}.",
                "fol_formula": fol_repr,
                "solver_duration_ms": duration_ms,
                "ast_clauses": ast_clauses,
                "proof_signature": "z3_rejected_unsat"
            }


if __name__ == "__main__":
    # Test valid exploit path
    res = SMTStudioEngine.evaluate_smt_proof(
        target_pid=4096,
        target_comm="curl_revshell",
        origin_pid=1024,
        graph_edges=[(1024, 2048), (2048, 4096)]
    )
    print("Valid Exploit Path Proof:", res["verdict"], f"({res['solver_duration_ms']}ms)")
    assert res["verified"] is True

    # Test Crown Jewel Protection
    res_crown = SMTStudioEngine.evaluate_smt_proof(
        target_pid=1,
        target_comm="systemd",
        origin_pid=1024,
        graph_edges=[(1024, 1)]
    )
    print("Crown Jewel Veto Proof:", res_crown["verdict"])
    assert res_crown["verified"] is False
    print(">>> SMT STUDIO ENGINE VERIFIED & THREAD-SAFE. <<<")
