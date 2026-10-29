"""
AegisKernel: Real-Time Dynamic Attack Blast-Radius Quantification Engine
=======================================================================
Calculates the instantaneous threat blast-radius score (R_blast) of an
investigated entity using graph spectral radius, privilege tier transitions,
spawned descendant fan-out, and active socket connections.

Formula:
  R_blast = w_priv * (1 + ln(1 + |children|)) * (1 + 0.5 * |sockets|) * S_spectral
"""

import math
from typing import Dict, List, Set, Any
import logging

logger = logging.getLogger("aegis-blast-radius")


class BlastRadiusCalculator:
    """
    Computes dynamic risk and blast-radius metrics over localized
    causal provenance subgraphs.
    """

    CROWN_JEWEL_PIDS = {1} # init/systemd
    CROWN_JEWEL_COMMS = {"systemd", "sshd", "etcd", "kubelet"}

    @classmethod
    def calculate_score(
        cls,
        target_pid: int,
        uid: int,
        comm: str,
        children: Set[int],
        sockets: Set[str],
        subgraph_nodes: List[Dict[str, Any]],
        subgraph_edges: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Computes the multi-factor blast radius score for a target entity.
        Returns score, risk classification, and contributing factors.
        """
        # 1. Privilege tier weight
        is_root = (uid == 0)
        privilege_weight = 3.5 if is_root else 1.0

        # 2. Process hierarchy descendant fan-out factor
        child_count = len(children)
        hierarchy_factor = 1.0 + math.log(1.0 + child_count)

        # 3. Network socket exposure factor
        socket_count = len(sockets)
        socket_factor = 1.0 + 0.5 * socket_count

        # 4. Graph spectral density approximation (degree centrality over k-hop subgraph)
        subgraph_node_count = max(1, len(subgraph_nodes))
        subgraph_edge_count = len(subgraph_edges)
        graph_density = (2.0 * subgraph_edge_count) / (subgraph_node_count * (subgraph_node_count + 1))
        spectral_factor = 1.0 + min(2.0, graph_density * 3.0)

        # Composite Blast-Radius Score
        r_blast = privilege_weight * hierarchy_factor * socket_factor * spectral_factor

        # Threat classification tier
        if r_blast >= 10.0:
            tier = "CRITICAL"
            recommendation = "AUTOMATED_CONTAINMENT_REQUIRED"
        elif r_blast >= 5.0:
            tier = "HIGH"
            recommendation = "AI_SWARM_INVESTIGATION_REQUIRED"
        elif r_blast >= 2.0:
            tier = "MEDIUM"
            recommendation = "ACTIVE_MONITORING"
        else:
            tier = "LOW"
            recommendation = "BASELINE_TELEMETRY"

        return {
            "target_pid": target_pid,
            "comm": comm,
            "uid": uid,
            "r_blast_score": round(r_blast, 3),
            "threat_tier": tier,
            "recommendation": recommendation,
            "metrics": {
                "privilege_weight": privilege_weight,
                "children_count": child_count,
                "sockets_count": socket_count,
                "subgraph_nodes": subgraph_node_count,
                "subgraph_edges": subgraph_edge_count,
            }
        }


if __name__ == "__main__":
    # Test 1: Unprivileged benign process
    res_benign = BlastRadiusCalculator.calculate_score(
        target_pid=2048,
        uid=1000,
        comm="vim",
        children=set(),
        sockets=set(),
        subgraph_nodes=[{"pid": 2048}],
        subgraph_edges=[]
    )
    print("Benign Score:", res_benign["r_blast_score"], "| Tier:", res_benign["threat_tier"])
    assert res_benign["threat_tier"] == "LOW"

    # Test 2: Escalated root attacker with 4 children and 2 outbound sockets
    res_malicious = BlastRadiusCalculator.calculate_score(
        target_pid=4096,
        uid=0, # Root
        comm="curl_miner",
        children={4097, 4098, 4099, 4100},
        sockets={"198.51.100.24:4444", "198.51.100.25:8080"},
        subgraph_nodes=[{"pid": 4096}, {"pid": 4097}, {"pid": 4098}, {"pid": 4099}, {"pid": 4100}],
        subgraph_edges=[{"src": 4096, "dst": 4097}, {"src": 4096, "dst": 4098}, {"src": 4096, "dst": 4099}, {"src": 4096, "dst": 4100}]
    )
    print("Malicious Score:", res_malicious["r_blast_score"], "| Tier:", res_malicious["threat_tier"])
    assert res_malicious["r_blast_score"] > 10.0
    assert res_malicious["threat_tier"] == "CRITICAL"
    print("Real-Time Attack Blast-Radius Quantification Engine verified successfully!")
