"""
AegisKernel: Real-Time Anomaly Innovation Evaluator
===================================================
Connects the Continuous-Time Temporal GNN (CT-HTGN) to the Multi-Agent
AI Swarm. Dispatches high-confidence anomaly alerts (p >= 0.80 or explicit
privilege escalations) for immediate L1 Triage and Z3 SMT Verification.
"""

from typing import Dict, Any, Optional
import time
import logging
from model import ContinuousTemporalGNN

logger = logging.getLogger("aegis-gnn-evaluator")


class AnomalyInnovationEvaluator:
    """
    Evaluates streaming GNN outputs and manages the threshold-triggered
    dispatch pipeline to the multi-agent AI swarm.
    """

    def __init__(self, anomaly_prob_threshold: float = 0.80):
        self.anomaly_prob_threshold = anomaly_prob_threshold
        self.gnn = ContinuousTemporalGNN(embedding_dim=64)
        self.total_evaluated = 0
        self.anomalies_flagged = 0

    def evaluate_kernel_event(
        self,
        src_pid: int,
        dst_pid: int,
        comm: str,
        event_type: str,
        timestamp_sec: Optional[float] = None
    ) -> Dict[str, Any]:
        """Evaluates an incoming event against continuous temporal memory."""
        ts = timestamp_sec or time.time()
        is_priv_esc = (event_type == "PrivilegeEscalation")

        result = self.gnn.process_event(
            src_id=src_pid,
            dst_id=dst_pid,
            event_type=event_type,
            current_time=ts,
            is_privilege_escalation=is_priv_esc
        )

        self.total_evaluated += 1

        # Alert triggered on high anomaly probability or privilege escalation
        is_alert = (result["anomaly_probability"] >= self.anomaly_prob_threshold) or is_priv_esc

        if is_alert:
            self.anomalies_flagged += 1
            logger.warning(
                "ANOMALY INNOVATION BOUNDARY BREACHED: PID %d -> PID %d (%s) | Prob: %.3f | Entropy: %.3f",
                src_pid, dst_pid, comm, result["anomaly_probability"], result["innovation_entropy"]
            )

        return {
            "evaluated_event": {
                "src_pid": src_pid,
                "dst_pid": dst_pid,
                "comm": comm,
                "event_type": event_type,
            },
            "gnn_metrics": result,
            "dispatch_to_swarm": is_alert,
            "recommended_action": "DISPATCH_AI_SWARM_TRIAGE" if is_alert else "BASELINE_CONTINUE",
        }


if __name__ == "__main__":
    evaluator = AnomalyInnovationEvaluator()

    # 1. Benign background events
    ev1 = evaluator.evaluate_kernel_event(src_pid=1, dst_pid=100, comm="systemd", event_type="ProcessExec")
    assert ev1["dispatch_to_swarm"] is False, "Benign event must not trigger alert"

    # 2. Anomalous privilege escalation event
    ev2 = evaluator.evaluate_kernel_event(src_pid=100, dst_pid=4096, comm="curl", event_type="PrivilegeEscalation")
    assert ev2["dispatch_to_swarm"] is True, "Privilege escalation must trigger alert"
    assert ev2["recommended_action"] == "DISPATCH_AI_SWARM_TRIAGE"

    print("Anomaly Innovation Evaluator passed verification! Flagged anomalies:", evaluator.anomalies_flagged)
