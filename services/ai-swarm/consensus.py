"""
AegisKernel: Multi-Agent Dynamic Bayesian Consensus Protocol
============================================================
Enforces cross-agent consensus between:
1. Triaging Agent (Noise filtering, initial anomaly scoring)
2. Deep Hunting Agent (Causal provenance path traversal)
3. Adversary Profiler (Deterministic MITRE ATT&CK attribution)

Requires Bayesian posterior consensus agreement > 0.85 and epistemic
uncertainty < 0.15 before containment recommendations can be passed
to the SMT First-Order Logic Verification Gate.
"""

from typing import Dict, List, Any, Tuple
from pydantic import BaseModel, Field
import math
import logging

logger = logging.getLogger("aegis-agent-consensus")


class AgentHypothesis(BaseModel):
    agent_id: str
    verdict: str  # "MALICIOUS", "SUSPICIOUS", "BENIGN"
    prior_confidence: float = Field(..., ge=0.0, le=1.0)
    epistemic_uncertainty: float = Field(..., ge=0.0, le=1.0)
    evidence_nodes: List[str]


class BayesianConsensusEngine:
    """
    Computes Bayesian posterior probability across heterogeneous agent hypotheses.
    """

    CONSENSUS_THRESHOLD = 0.85
    UNCERTAINTY_CEILING = 0.15

    @classmethod
    def evaluate_consensus(
        cls,
        hypotheses: List[AgentHypothesis]
    ) -> Tuple[bool, float, float, str]:
        """
        Synthesizes agent opinions using a weighted Bayesian log-odds aggregator.
        Returns: (ConsensusReached, PosteriorProbability, AggregateUncertainty, ConsensusSummary)
        """
        if not hypotheses:
            return False, 0.0, 1.0, "REJECTED: No agent hypotheses provided"

        log_odds_sum = 0.0
        weighted_uncertainties = []

        for h in hypotheses:
            # Weight inversely proportional to epistemic uncertainty
            weight = 1.0 / (h.epistemic_uncertainty + 1e-4)
            weighted_uncertainties.append(h.epistemic_uncertainty)

            # Convert prior confidence to log-odds
            p = max(1e-4, min(1.0 - 1e-4, h.prior_confidence))
            log_odds = math.log(p / (1.0 - p))

            if h.verdict == "MALICIOUS":
                log_odds_sum += weight * log_odds
            elif h.verdict == "BENIGN":
                log_odds_sum -= weight * abs(log_odds)

        # Convert composite log-odds back to posterior probability
        total_weight = sum(1.0 / (u + 1e-4) for u in weighted_uncertainties)
        normalized_log_odds = log_odds_sum / total_weight

        posterior_prob = 1.0 / (1.0 + math.exp(-normalized_log_odds))
        aggregate_uncertainty = sum(weighted_uncertainties) / len(weighted_uncertainties)

        is_consensus = (
            posterior_prob >= cls.CONSENSUS_THRESHOLD and
            aggregate_uncertainty <= cls.UNCERTAINTY_CEILING
        )

        summary = (
            f"Posterior: {posterior_prob:.3f} | Uncertainty: {aggregate_uncertainty:.3f} | "
            f"Consensus: {'REACHED' if is_consensus else 'UNRESOLVED'}"
        )

        logger.info("Bayesian Consensus Result: %s", summary)
        return is_consensus, round(posterior_prob, 3), round(aggregate_uncertainty, 3), summary


if __name__ == "__main__":
    # Test 1: Strong agreement between Triager, Hunter, and Profiler
    valid_swarm = [
        AgentHypothesis(agent_id="triager", verdict="MALICIOUS", prior_confidence=0.92, epistemic_uncertainty=0.08, evidence_nodes=["Node_A"]),
        AgentHypothesis(agent_id="hunter", verdict="MALICIOUS", prior_confidence=0.88, epistemic_uncertainty=0.10, evidence_nodes=["Node_A", "Node_B"]),
        AgentHypothesis(agent_id="profiler", verdict="MALICIOUS", prior_confidence=0.95, epistemic_uncertainty=0.05, evidence_nodes=["Node_B"]),
    ]
    consensus, prob, unc, msg = BayesianConsensusEngine.evaluate_consensus(valid_swarm)
    print("Test 1 (Agreement):", msg)
    assert consensus is True
    assert prob >= 0.85

    # Test 2: Conflict between Triager and Hunter (Triager says Benign)
    conflicting_swarm = [
        AgentHypothesis(agent_id="triager", verdict="BENIGN", prior_confidence=0.85, epistemic_uncertainty=0.10, evidence_nodes=["Node_A"]),
        AgentHypothesis(agent_id="hunter", verdict="MALICIOUS", prior_confidence=0.60, epistemic_uncertainty=0.40, evidence_nodes=["Node_A"]),
    ]
    consensus_fail, prob_fail, unc_fail, msg_fail = BayesianConsensusEngine.evaluate_consensus(conflicting_swarm)
    print("Test 2 (Conflict):", msg_fail)
    assert consensus_fail is False
    print("Multi-Agent Dynamic Bayesian Consensus Protocol verified successfully!")
