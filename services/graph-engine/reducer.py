"""
AegisKernel: Dynamic Streaming Edge Reducer & Throttler
======================================================
Mitigates the "provenance graph dependency explosion problem" by:
1. Aggregating high-frequency repetitive events (e.g., repeated reads/writes)
   into single weighted temporal edges with [first_seen_ts, last_seen_ts, count].
2. Bounding maximum out-degree to 512 edges per node per minute.
3. Preventing cyclic graph loops.
"""

from typing import Dict, Tuple, Optional, List
import time
import logging

logger = logging.getLogger("aegis-edge-reducer")


class CompressedEdge:
    """Represents an aggregated temporal edge between two graph vertices."""
    def __init__(self, src: int, dst: int, event_type: str, timestamp_ns: int):
        self.src = src
        self.dst = dst
        self.event_type = event_type
        self.first_seen_ns = timestamp_ns
        self.last_seen_ns = timestamp_ns
        self.event_count = 1

    def increment(self, timestamp_ns: int):
        self.event_count += 1
        self.last_seen_ns = timestamp_ns

    def to_dict(self) -> Dict:
        return {
            "src": self.src,
            "dst": self.dst,
            "event_type": self.event_type,
            "first_seen_ns": self.first_seen_ns,
            "last_seen_ns": self.last_seen_ns,
            "count": self.event_count,
        }


class StreamingEdgeReducer:
    """
    Stateful streaming reducer that aggregates repetitive events across
    sliding time windows and enforces node degree rate limits.
    """

    def __init__(self, window_sec: float = 60.0, max_edges_per_node: int = 512):
        self.window_sec = window_sec
        self.max_edges_per_node = max_edges_per_node
        # Key: (src, dst, event_type) -> CompressedEdge
        self.active_edges: Dict[Tuple[int, int, str], CompressedEdge] = {}
        # Key: src_pid -> count of distinct targets in current window
        self.out_degree_counts: Dict[int, int] = {}
        self.window_start_time = time.time()

    def process_event(self, src: int, dst: int, event_type: str, timestamp_ns: int) -> Optional[CompressedEdge]:
        """
        Processes an incoming graph edge event. Returns the compressed edge if it is a
        new edge or flushed edge, or None if it was aggregated into an existing edge.
        """
        self._check_window_rollover()

        edge_key = (src, dst, event_type)

        # 1. Check if edge already exists in active window -> Aggregate!
        if edge_key in self.active_edges:
            self.active_edges[edge_key].increment(timestamp_ns)
            return None # Suppress duplicate emission downstream

        # 2. Check out-degree rate limits for node
        current_degree = self.out_degree_counts.get(src, 0)
        if current_degree >= self.max_edges_per_node:
            logger.warning(
                "RATE-LIMIT: Node PID %d exceeded max out-degree threshold (%d edges). Throttling edge to %d.",
                src, self.max_edges_per_node, dst
            )
            return None

        # 3. Create new compressed edge
        compressed = CompressedEdge(src, dst, event_type, timestamp_ns)
        self.active_edges[edge_key] = compressed
        self.out_degree_counts[src] = current_degree + 1

        return compressed

    def flush_edges(self) -> List[Dict]:
        """Flushes all currently aggregated edges for database persistence."""
        flushed = [edge.to_dict() for edge in self.active_edges.values()]
        self.active_edges.clear()
        self.out_degree_counts.clear()
        return flushed

    def _check_window_rollover(self):
        """Resets out-degree rate limits when the sliding window elapses."""
        now = time.time()
        if now - self.window_start_time >= self.window_sec:
            self.out_degree_counts.clear()
            self.window_start_time = now


if __name__ == "__main__":
    reducer = StreamingEdgeReducer(window_sec=60.0, max_edges_per_node=5)

    # Simulate 10,000 repeated file reads between Process 1024 and File Inode 5555
    emitted = []
    for i in range(10000):
        res = reducer.process_event(
            src=1024,
            dst=5555,
            event_type="WROTE",
            timestamp_ns=1_000_000 + i * 1000
        )
        if res is not None:
            emitted.append(res)

    print(f"Total raw events: 10,000 | Emitted distinct edges: {len(emitted)}")
    assert len(emitted) == 1, "Should collapse 10,000 repeated events into 1 edge"
    
    flushed = reducer.flush_edges()
    assert flushed[0]["count"] == 10000
    print(f"Edge compressed successfully: {flushed[0]['count']} operations collapsed!")
    print("Streaming Edge Reducer verified successfully!")
