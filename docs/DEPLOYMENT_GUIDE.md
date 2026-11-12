# AegisKernel: Cloud Deployment & Cron Job Operations Guide
## Vercel, Render, Kubernetes, and Automated Cron Jobs
**Document Version:** 1.0.0  
**Target Systems:** Vercel, Render.com, GitHub Actions Cron, Linux Host / K8s  

---

## 1. VERCEL DEPLOYMENT (SOC Dashboard Frontend)

Vercel provides instant edge hosting for the Next.js 15 3D WebGL Threat Hunting Dashboard (`web/soc-dashboard`).

### Method A: Deploy via Vercel Web Dashboard (1-Click)
1. Navigate to [vercel.com/new](https://vercel.com/new) and select the `AegisKernel` repository.
2. Under **Root Directory**, click **Edit** and set it to:
   ```
   web/soc-dashboard
   ```
3. Framework Preset: **Next.js** (automatically detected).
4. **Environment Variables**:
   * `NEXT_PUBLIC_API_URL`: URL of your deployed Render backend (e.g., `https://aegis-control-plane.onrender.com`).
5. Click **Deploy**.

### Method B: Deploy via Vercel CLI
```bash
# Navigate to the dashboard directory
cd web/soc-dashboard

# Install Vercel CLI if not already installed
npm install -g vercel

# Deploy to Preview
vercel

# Deploy to Production
vercel --prod
```

The configuration is pre-configured via [`web/soc-dashboard/vercel.json`](file:///d:/internship%20project%20%20soc/web/soc-dashboard/vercel.json) and root [`vercel.json`](file:///d:/internship%20project%20%20soc/vercel.json).

---

## 2. RENDER DEPLOYMENT (Full-Stack Backend + Dashboard + Cron)

Render supports multi-service declarative infrastructure using Infrastructure-as-Code via [`render.yaml`](file:///d:/internship%20project%20%20soc/render.yaml).

### 1-Click Blueprint Deployment:
1. Push your latest code to your GitHub repository (`origin/master`).
2. Log into [dashboard.render.com](https://dashboard.render.com).
3. Click **New +** $\to$ **Blueprint**.
4. Connect your `AegisKernel` GitHub repository.
5. Render will automatically detect [`render.yaml`](file:///d:/internship%20project%20%20soc/render.yaml) and declare three services:
   * **`aegis-control-plane`** (Python Web Service):
     - Command: `uvicorn agency.company.server:app --host 0.0.0.0 --port $PORT`
     - Auto-generates `AEGIS_API_TOKEN` for zero-trust security.
   * **`aegis-soc-dashboard`** (Node.js Web Service):
     - Root Dir: `web/soc-dashboard`
     - Command: `npm install && npm run build && npm run start -- -p $PORT`
     - Auto-wires `NEXT_PUBLIC_API_URL` to the control plane.
   * **`aegis-threat-hunt-cron`** (Cron Job):
     - Schedule: `0 */6 * * *` (Every 6 hours)
     - Command: `python scripts/run_e2e_simulation.py`
6. Click **Apply** to deploy the entire stack.

---

## 3. SCHEDULED CRON JOB AUTOMATION

AegisKernel features two automated cron execution mechanisms:

### 1. GitHub Actions Scheduled Cron (`.github/workflows/scheduled_audit_cron.yml`)
* **Schedule:** `0 */6 * * *` (Runs every 6 hours automatically).
* **Manual Trigger:** Supported via `workflow_dispatch` button under the GitHub Actions tab.
* **Automated Tasks Executed:**
  - Full end-to-end multi-stage APT attack and kernel deception simulation (`scripts/run_e2e_simulation.py`).
  - Cryptographic Evidence Vault HMAC-SHA256 signature chain verification (`services/forensics/evidence_vault.py`).
  - Z3 SMT Formal reachability invariant safety proofs (`services/ai-swarm/swarm.py`).
  - Bayesian consensus engine sanity checks (`services/ai-swarm/consensus.py`).

### 2. Linux Systemd / Crontab (On-Premises Sensor Fleet)
To run local threat hunting every night at 2:00 AM on your Linux sensor host:
```bash
# Add to host crontab (crontab -e)
0 2 * * * cd /opt/aegis-kernel && /opt/aegis-kernel/.venv/bin/python scripts/run_e2e_simulation.py >> /var/log/aegis_cron.log 2>&1
```

---

## 4. LOCAL DOCKER COMPOSE VERIFICATION

To run and verify the entire fleet locally before pushing to production:
```bash
# Build and launch all services: Rust agent, Redpanda, Memgraph, FastAPI, and Dashboard
docker-compose -f deploy/docker-compose.yml up --build -d

# Verify running health
docker-compose -f deploy/docker-compose.yml ps

# View live telemetry streams
docker-compose -f deploy/docker-compose.yml logs -f aegis-agent
```
