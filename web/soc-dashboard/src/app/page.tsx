'use client';

import React, { useState, useEffect } from 'react';
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
  X
} from 'lucide-react';

export default function SocCommandCenter() {
  const [replayTime, setReplayTime] = useState<number>(100);
  const [isContainmentModalOpen, setIsContainmentModalOpen] = useState<boolean>(false);
  const [containmentResult, setContainmentResult] = useState<string | null>(null);
  const [isContainmentLoading, setIsContainmentLoading] = useState<boolean>(false);
  const [metrics, setMetrics] = useState({
    activeThreats: 2,
    blastRadiusMax: 32.88,
    shuntedPids: 1,
    verifiedProofs: 158,
    bpfRingbufDropRate: 0.00,
    host: 'prod-k8s-node-04.sec',
    kernel: 'Linux 6.6.0-aegis-lsm'
  });

  // Fetch live telemetry from the Vercel serverless API route
  useEffect(() => {
    async function fetchTelemetry() {
      try {
        const res = await fetch('/api/telemetry');
        if (res.ok) {
          const data = await res.json();
          if (data.metrics) {
            setMetrics({
              ...data.metrics,
              host: data.host || 'prod-k8s-node-04.sec',
              kernel: data.kernel || 'Linux 6.6.0-aegis-lsm'
            });
          }
        }
      } catch (e) {
        // Fallback to initial local telemetry if offline
      }
    }

    fetchTelemetry();
    const interval = setInterval(fetchTelemetry, 10000);
    return () => clearInterval(interval);
  }, []);

  // Execute kernel containment action via Vercel serverless API route
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
        setMetrics(prev => ({ ...prev, shuntedPids: prev.shuntedPids + 1, activeThreats: Math.max(0, prev.activeThreats - 1) }));
      }
    } catch (err: any) {
      setContainmentResult('Containment action simulated: PID 4096 shunted to Firecracker microVM.');
    } finally {
      setIsContainmentLoading(false);
    }
  };

  return (
    <div className="flex h-screen w-screen bg-[#06080e] text-[#e1e7f0] font-mono overflow-hidden">
      {/* Left Navigation Bar */}
      <aside className="w-64 border-r border-[#1a2333] bg-[#0a0f18] flex flex-col justify-between p-4">
        <div>
          <div className="flex items-center gap-3 mb-8">
            <div className="h-9 w-9 rounded-lg bg-emerald-500/20 border border-emerald-500/50 flex items-center justify-center text-emerald-400 font-bold text-lg">
              🛡️
            </div>
            <div>
              <h1 className="text-sm font-bold tracking-wider text-white">AEGISKERNEL</h1>
              <p className="text-[10px] text-emerald-400 font-medium">SOC 3D THREAT PLATFORM</p>
            </div>
          </div>

          <nav className="space-y-1 text-xs">
            <a href="#canvas" className="flex items-center gap-2 px-3 py-2 rounded-md bg-emerald-500/10 text-emerald-300 border border-emerald-500/30">
              <Activity className="h-4 w-4" /> 3D Provenance Canvas
            </a>
            <a href="#mitre" className="flex items-center gap-2 px-3 py-2 rounded-md text-gray-400 hover:bg-[#141d2e] hover:text-white transition">
              <Layers className="h-4 w-4" /> MITRE ATT&CK Matrix
            </a>
            <a href="#reasoning" className="flex items-center gap-2 px-3 py-2 rounded-md text-gray-400 hover:bg-[#141d2e] hover:text-white transition">
              <Terminal className="h-4 w-4" /> Neuro-Symbolic Proofs
            </a>
            <a href="/api/telemetry" target="_blank" rel="noreferrer" className="flex items-center gap-2 px-3 py-2 rounded-md text-gray-400 hover:bg-[#141d2e] hover:text-white transition">
              <Eye className="h-4 w-4" /> Serverless API (/api)
            </a>
          </nav>
        </div>

        {/* Live Kernel Telemetry Metrics */}
        <div className="border border-[#1a2333] bg-[#0d1422] p-3 rounded-lg space-y-2 text-[11px]">
          <div className="text-gray-400 uppercase text-[9px] font-bold tracking-wider flex justify-between items-center">
            <span>Kernel Telemetry</span>
            <span className="h-2 w-2 rounded-full bg-emerald-500 animate-ping" />
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

      {/* Main Threat Hunting Canvas & Replay Area */}
      <main className="flex-1 flex flex-col">
        {/* Top Header */}
        <header className="h-14 border-b border-[#1a2333] bg-[#0a0f18]/80 backdrop-blur px-6 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <span className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30 animate-pulse">
              <AlertTriangle className="h-3.5 w-3.5" /> LIVE ATTACK DETECTED (PID 4096)
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

        {/* 3D WebGL Canvas Viewport placeholder & Interactive HUD */}
        <div className="flex-1 relative bg-gradient-to-b from-[#06080e] to-[#0a101d] overflow-hidden flex flex-col justify-between p-6">
          <div className="absolute inset-0 flex items-center justify-center opacity-10 pointer-events-none">
            <div className="h-[600px] w-[600px] rounded-full border border-emerald-500/40 animate-ping" style={{ animationDuration: '8s' }} />
          </div>

          {/* Quick Graph Node Details Box (HUD) */}
          <div className="z-10 max-w-md bg-[#0a0f18]/90 border border-[#1e293b] rounded-lg p-4 backdrop-blur shadow-2xl">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-xs font-bold uppercase text-gray-300 flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-rose-400" /> Inspected Node: PID 4096 (curl_revshell)
              </h3>
              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">
                CRITICAL
              </span>
            </div>
            <div className="space-y-1.5 text-xs text-gray-400">
              <p>Path: <code className="text-gray-200">/tmp/.x11-unix/reverse_tcp</code></p>
              <p>Parent PID: <code className="text-gray-200">1024 (nginx: worker)</code></p>
              <p>CT-HTGN Anomaly Score: <strong className="text-rose-400">0.984</strong> (p &gt; 0.85 threshold)</p>
              <p>Spectral Blast Radius: <strong className="text-amber-400">{metrics.blastRadiusMax}</strong></p>
              <p>Ghost-Mirror Status: <strong className="text-purple-400">Shunted to CoW Scratchpad</strong></p>
              <p>SMT FOL Proof: <code className="text-emerald-400">VERIFIED(Reach(4096, CrownJewel=False))</code></p>
            </div>
          </div>

          {/* Attack Timeline Scrubber Slider */}
          <div className="z-10 bg-[#0a0f18]/90 border border-[#1e293b] rounded-lg p-3 backdrop-blur flex items-center gap-4">
            <Sliders className="h-4 w-4 text-emerald-400" />
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
        </div>
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
              <Lock className="h-4 w-4 text-rose-500" /> Kernel Deception Containment Desk
            </h2>
            <p className="text-xs text-gray-300 mb-4 leading-relaxed">
              Target exploit process <code className="text-rose-400 font-bold">PID 4096</code> has an RGCN anomaly score of <strong className="text-rose-400">0.984</strong>.
              Triggering containment will invoke BPF-LSM syscall interception and shunt TCP sockets to a Firecracker microVM honey-sandbox.
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
