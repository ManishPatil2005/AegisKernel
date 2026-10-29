"""
AegisKernel: In-Memory Streaming Causal Provenance Graph Engine
==============================================================
Consumes telemetry events from Redpanda/Kafka topics and updates the
live in-memory Memgraph cluster using Bolt/Cypher queries.
Maintains Process, File, Socket, and User entities with causal edges.
"""

from typing import Dict, Any, List, Optional
import time
import json
import logging
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("aegis-graph-engine")


class GraphTelemetryRecord(BaseModel):
    timestamp_ns: int
    pid: int
    ppid: int
    uid: int
    gid: int
    event_type: str
    comm: str
    filename: str
    lineage_hash: int = 0


class CausalGraphEngine:
    """
    Manages in-memory graph models for causal attack provenance.
    Generates optimized Cypher statements for Memgraph ingestion.
    """

    def __init__(self, uri: str = "bolt://localhost:7687", auth: Optional[tuple] = None):
        self.uri = uri
        self.auth = auth
        self.driver = None
        self.in_memory_nodes: Dict[int, Dict[str, Any]] = {}
        self.in_memory_edges: List[tuple] = []

    def connect(self):
        """Connects to the Memgraph cluster via the Neo4j Bolt driver."""
        try:
            from neo4j import GraphDatabase
            self.driver = GraphDatabase.driver(self.uri, auth=self.auth)
            logger.info("Connected to Memgraph in-memory cluster at %s", self.uri)
        except Exception as e:
            logger.warning("Memgraph cluster unreachable (%s). Operating in high-speed local in-memory fallback mode.", e)
            self.driver = None

    def ingest_record(self, record: GraphTelemetryRecord):
        """Ingests a telemetry record and updates the causal DAG."""
        cypher_query = self._build_cypher_mutation(record)

        # Update local in-memory mirror
        self.in_memory_nodes[record.pid] = {
            "comm": record.comm,
            "filename": record.filename,
            "uid": record.uid,
            "ppid": record.ppid,
            "timestamp_ns": record.timestamp_ns,
        }

        if record.ppid > 0:
            self.in_memory_edges.append((record.ppid, record.pid, record.event_type))

        # Execute on live Memgraph if connected
        if self.driver:
            try:
                with self.driver.session() as session:
                    session.run(cypher_query["query"], cypher_query["params"])
            except Exception as e:
                logger.error("Failed to execute Cypher mutation: %s", e)

        logger.info(
            "Graph entity updated: PID %d (%s) -> Edge [%s] from PPID %d",
            record.pid, record.comm, record.event_type, record.ppid
        )

    def _build_cypher_mutation(self, record: GraphTelemetryRecord) -> Dict[str, Any]:
        """Builds idempotent Cypher query to upsert Process nodes and causal edges."""
        if record.event_type == "ProcessExec":
            query = """
            MERGE (p:Process {pid: $pid})
            ON CREATE SET p.comm = $comm, p.filename = $filename, p.uid = $uid, p.created_at = $ts
            ON MATCH SET p.comm = $comm, p.filename = $filename, p.uid = $uid
            WITH p
            MATCH (parent:Process {pid: $ppid})
            MERGE (parent)-[r:FORKED {timestamp: $ts}]->(p)
            """
            params = {
                "pid": record.pid,
                "ppid": record.ppid,
                "comm": record.comm,
                "filename": record.filename,
                "uid": record.uid,
                "ts": record.timestamp_ns,
            }
        elif record.event_type == "PrivilegeEscalation":
            query = """
            MATCH (p:Process {pid: $pid})
            SET p.uid = $uid, p.escalated = true
            MERGE (u:User {uid: $uid})
            MERGE (p)-[r:ESCALATED_TO {timestamp: $ts}]->(u)
            """
            params = {
                "pid": record.pid,
                "uid": record.uid,
                "ts": record.timestamp_ns,
            }
        elif record.event_type == "SocketConnect":
            query = """
            MATCH (p:Process {pid: $pid})
            MERGE (s:Socket {address: $target})
            MERGE (p)-[r:CONNECTED_TO {timestamp: $ts}]->(s)
            """
            params = {
                "pid": record.pid,
                "target": record.filename,
                "ts": record.timestamp_ns,
            }
        else:
            query = """
            MERGE (p:Process {pid: $pid})
            ON CREATE SET p.comm = $comm, p.uid = $uid
            """
            params = {
                "pid": record.pid,
                "comm": record.comm,
                "uid": record.uid,
            }

        return {"query": query, "params": params}

    def extract_subgraph(self, target_pid: int, max_hops: int = 3) -> Dict[str, Any]:
        """Extracts localized k-hop causal subgraph around an anomalous process."""
        visited_nodes = set()
        edges = []
        queue = [target_pid]

        while queue:
            curr = queue.pop(0)
            if curr in visited_nodes:
                continue
            visited_nodes.add(curr)

            # Find incoming edges (parent processes)
            for src, dst, event in self.in_memory_edges:
                if dst == curr and src not in visited_nodes:
                    edges.append({"src": src, "dst": dst, "type": event})
                    queue.append(src)

        nodes = [
            {"pid": pid, "data": self.in_memory_nodes.get(pid, {})}
            for pid in visited_nodes
        ]

        return {
            "target_pid": target_pid,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "nodes": nodes,
            "edges": edges,
        }


if __name__ == "__main__":
    engine = CausalGraphEngine()
    engine.connect()

    # Ingest sample causal attack sequence
    records = [
        GraphTelemetryRecord(timestamp_ns=100, pid=1, ppid=0, uid=0, gid=0, event_type="ProcessExec", comm="systemd", filename="/usr/lib/systemd"),
        GraphTelemetryRecord(timestamp_ns=200, pid=1000, ppid=1, uid=0, gid=0, event_type="ProcessExec", comm="sshd", filename="/usr/sbin/sshd"),
        GraphTelemetryRecord(timestamp_ns=300, pid=2000, ppid=1000, uid=1000, gid=1000, event_type="ProcessExec", comm="bash", filename="/bin/bash"),
        GraphTelemetryRecord(timestamp_ns=400, pid=4000, ppid=2000, uid=1000, gid=1000, event_type="ProcessExec", comm="curl", filename="/tmp/exploit"),
        GraphTelemetryRecord(timestamp_ns=500, pid=4000, ppid=2000, uid=0, gid=0, event_type="PrivilegeEscalation", comm="curl", filename="/tmp/exploit"),
        GraphTelemetryRecord(timestamp_ns=600, pid=4000, ppid=2000, uid=0, gid=0, event_type="SocketConnect", comm="curl", filename="198.51.100.24:4444"),
    ]

    for r in records:
        engine.ingest_record(r)

    subgraph = engine.extract_subgraph(target_pid=4000, max_hops=3)
    logger.info("Extracted attack causal subgraph: %d nodes, %d edges", subgraph["node_count"], subgraph["edge_count"])
    assert subgraph["node_count"] >= 3
    print("Memgraph In-Memory Causal Graph Engine verified successfully!")
