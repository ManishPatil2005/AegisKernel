import { NextResponse } from 'next/server';

export const runtime = 'edge';

export async function GET() {
  const telemetryData = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    host: 'prod-k8s-node-04.sec',
    kernel: 'Linux 6.6.0-aegis-lsm',
    metrics: {
      activeThreats: 2,
      blastRadiusMax: 32.88,
      shuntedPids: 1,
      verifiedProofs: 158,
      bpfRingbufDropRate: 0.00,
      eventsPerSec: 14250,
      cpuUsagePct: 1.2,
      memUsageMb: 78.4
    },
    activeIncident: {
      pid: 4096,
      name: 'curl_revshell',
      path: '/tmp/.x11-unix/reverse_tcp',
      parentPid: 1024,
      parentName: 'nginx: worker',
      anomalyScore: 0.984,
      severity: 'CRITICAL',
      status: 'Shunted to CoW Scratchpad',
      smtProof: 'VERIFIED(Reach(4096, CrownJewel=False))'
    }
  };

  return NextResponse.json(telemetryData, {
    headers: {
      'Cache-Control': 'no-store, max-age=0',
      'Access-Control-Allow-Origin': '*'
    }
  });
}
