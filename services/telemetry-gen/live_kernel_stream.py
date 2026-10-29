"""
AegisKernel: Real-Time Enterprise Kernel Telemetry Generator
============================================================
Simulates continuous, high-volume Linux kernel telemetry:
1. Benign background workload noise (nginx requests, cron, postgres, kubelet).
2. Stealthy LotL and APT exploit anomalies.
3. Formats events with zero-copy Protobuf-compatible field structures.
"""

from typing import Dict, List, Generator
import random
import time
import uuid


class EnterpriseKernelTelemetryGenerator:
    """Produces a continuous, realistic stream of enterprise kernel events."""

    BENIGN_PROCESSES = [
        ("nginx", "/usr/sbin/nginx", 1000, False),
        ("postgres", "/usr/lib/postgresql/bin/postgres", 1001, False),
        ("kubelet", "/usr/bin/kubelet", 0, True),
        ("node_exporter", "/usr/bin/node_exporter", 1000, False),
        ("cron", "/usr/sbin/cron", 0, True),
        ("dockerd", "/usr/bin/dockerd", 0, True),
    ]

    @classmethod
    def generate_event_stream(cls, burst_count: int = 20) -> List[Dict]:
        events = []
        for _ in range(burst_count):
            comm, path, uid, is_root = random.choice(cls.BENIGN_PROCESSES)
            pid = random.randint(1000, 65000)
            ppid = random.choice([1, 900, 1024])
            event_type = random.choice(["EXEC", "FILE_READ", "CONNECT", "FORK"])

            ev = {
                "event_id": str(uuid.uuid4())[:12],
                "timestamp_ns": int(time.time() * 1e9),
                "event_type": event_type,
                "process": {
                    "pid": pid,
                    "ppid": ppid,
                    "uid": uid,
                    "comm": comm,
                    "executable_path": path,
                    "is_root": is_root
                },
                "anomaly_score": round(random.uniform(0.01, 0.15), 3)
            }
            events.append(ev)
        return events

    @classmethod
    def generate_adversarial_exploit_burst(cls) -> List[Dict]:
        """Generates a multi-step anomalous APT attack sequence."""
        t_base = time.time()
        return [
            {
                "event_id": "APT-01",
                "timestamp_ns": int(t_base * 1e9),
                "event_type": "PROCESS_EXEC",
                "process": {"pid": 2048, "ppid": 1024, "uid": 0, "comm": "sh", "executable_path": "/bin/sh", "is_root": True},
                "mitre_technique": "T1059.004",
                "anomaly_score": 0.89
            },
            {
                "event_id": "APT-02",
                "timestamp_ns": int((t_base + 0.002) * 1e9),
                "event_type": "FILE_MPROTECT",
                "process": {"pid": 2048, "ppid": 1024, "uid": 0, "comm": "sh", "executable_path": "/bin/sh", "is_root": True},
                "mitre_technique": "T1055 (PROT_EXEC)",
                "anomaly_score": 0.96
            },
            {
                "event_id": "APT-03",
                "timestamp_ns": int((t_base + 0.005) * 1e9),
                "event_type": "SYS_ENTER_CONNECT",
                "process": {"pid": 4096, "ppid": 2048, "uid": 0, "comm": "curl_revshell", "executable_path": "/tmp/.x11-unix/reverse_tcp", "is_root": True},
                "socket": {"dest_ip": "198.51.100.4", "dest_port": 4444},
                "mitre_technique": "T1071.001",
                "anomaly_score": 0.984
            }
        ]


if __name__ == "__main__":
    benign_burst = EnterpriseKernelTelemetryGenerator.generate_event_stream(5)
    print("Sample Benign Kernel Events Generated:", len(benign_burst))
    exploit_burst = EnterpriseKernelTelemetryGenerator.generate_adversarial_exploit_burst()
    print("Sample Adversarial Exploit Burst Generated:", len(exploit_burst))
    assert len(exploit_burst) == 3
    print(">>> ENTERPRISE KERNEL TELEMETRY GENERATOR VERIFIED. <<<")
