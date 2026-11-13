# AegisKernel: Complete Cloud Deployment & Architecture Guide
## Vercel vs. Render vs. Hybrid: Which Do You Need?

**Target Platforms:** Vercel, Render.com, GitHub Actions  
**Repository:** `https://github.com/ManishPatil2005/AegisKernel`  
**Latest Version:** 3.1.0-PRODUCTION  

---

## 0. THE CORE QUESTION: DO YOU NEED BOTH, OR DOES ONLY ONE WORK?

| Deployment Strategy | Frontend (Next.js) | Backend (FastAPI) | Cron Job | Can It Work Alone? | Recommended For |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **OPTION 1: ONLY VERCEL** | **Active on Vercel** | Offline / Mock | GitHub Actions | **YES (Standalone UI)** | Fast supervisor presentation, UI demo, portfolio preview |
| **OPTION 2: ONLY RENDER** | **Active on Render** | **Active on Render** | **Active on Render** | **YES (All-In-One)** | Single cloud provider, zero-maintenance, complete backend + UI |
| **OPTION 3: BOTH (HYBRID)** | **Vercel (Global Edge)** | **Render (Compute)** | **Render / GitHub** | **YES (Production Tier)** | Enterprise standard: high-speed edge frontend + Python backend |

---

## 1. DETAILED BREAKDOWN OF EACH DEPLOYMENT OPTION

---

### OPTION 1: DEPLOYING ONLY ON VERCEL (FRONTEND ONLY)

#### Can Vercel run alone without a backend?
**YES.**  
The Next.js 15 SOC Threat-Hunting Dashboard (`web/soc-dashboard`) is designed to render standalone. It includes full client-side state for:
- 3D Threat Hunting Viewport
- Inspected Node HUD (PID 4096 reverse shell)
- Dynamic Causal Replay Scrubber (0% to 100%)
- Live telemetry metrics (Exploit paths, $R_{\text{blast}}$, RingBuf drop rate)
- MITRE ATT&CK matrix and neuro-symbolic proof cards

#### Step-by-Step Instructions to Deploy on Vercel:
1. Open [vercel.com](https://vercel.com) and log in with your GitHub account.
2. Click **Add New...** $\to$ **Project**.
3. Select the `AegisKernel` repository from the list.
4. In the **Configure Project** screen:
   * **Project Name:** `aegis-soc-dashboard`
   * **Framework Preset:** **Next.js** (Automatically detected)
   * **Root Directory:** Click **Edit** and choose `web/soc-dashboard`. *(CRITICAL STEP)*
5. **Build and Output Settings:** Leave default (`npm run build`).
6. **Environment Variables:** (Optional for standalone mode)
   * `NEXT_PUBLIC_API_URL`: (Leave empty or set to any backend URL later).
7. Click **Deploy**.
8. **Result:** In under 60 seconds, you get a live global URL:
   `https://aegis-soc-dashboard.vercel.app`

---

### OPTION 2: DEPLOYING ONLY ON RENDER (ALL-IN-ONE FULL-STACK)

#### Can Render run alone without Vercel?
**YES.**  
Render is a full cloud provider capable of running:
1. Python FastAPI Backend Service (`agency/company/server.py`)
2. Node.js Next.js Frontend Service (`web/soc-dashboard`)
3. Built-in HTML Operator Console (`agency/company/static/v2_console.html`)
4. Automated Threat Hunting Cron Job (`aegis-threat-hunt-cron`)

By using Render, you do **NOT** need Vercel at all because Render hosts the entire stack in one place.

#### Step-by-Step Instructions to Deploy on Render (1-Click Blueprint):
1. Push all code to your GitHub repository (`origin/master`).
2. Log into [dashboard.render.com](https://dashboard.render.com).
3. Click **New +** (top right) $\to$ **Blueprint**.
4. Connect your `AegisKernel` GitHub repository.
5. Render will automatically detect [`render.yaml`](file:///d:/internship%20project%20%20soc/render.yaml) in the root of the repository.
6. Render will display the 3 services defined in the blueprint:
   * `aegis-control-plane` (Python Web Service)
   * `aegis-soc-dashboard` (Node.js Web Service)
   * `aegis-threat-hunt-cron` (Recurring Cron Job every 6 hours)
7. Click **Apply**.
8. Render will provision and launch all 3 components.
9. **Result:**
   * Backend API: `https://aegis-control-plane.onrender.com`
   * Next.js Dashboard: `https://aegis-soc-dashboard.onrender.com`
   * Live Operator Console: `https://aegis-control-plane.onrender.com/console`

---

### OPTION 3: DEPLOYING BOTH (HYBRID PRODUCTION ARCHITECTURE)

#### Why deploy on both?
This is the industry-standard architecture used by top modern tech companies:
* **Vercel** provides the world's fastest global CDN edge network for the Next.js React frontend (zero latency loading anywhere in the world).
* **Render** handles persistent long-running Python processes, WebSockets, background tasks, and cron jobs.

#### Step-by-Step Setup for Both:
1. **Deploy Backend on Render First:**
   * In Render, create a Web Service from the repository:
     - Runtime: `Python 3`
     - Build Command: `pip install -r agency/company/requirements.txt`
     - Start Command: `uvicorn agency.company.server:app --host 0.0.0.0 --port $PORT`
   * Copy your live Render URL: e.g., `https://aegis-control-plane.onrender.com`.

2. **Deploy Frontend on Vercel Second:**
   * In Vercel, import the repo and set Root Directory to `web/soc-dashboard`.
   * Add Environment Variable:
     ```
     NEXT_PUBLIC_API_URL = https://aegis-control-plane.onrender.com
     ```
   * Click **Deploy**.

3. **Result:**
   The Vercel frontend automatically talks to the live Render backend over HTTPS.

---

## 2. SUMMARY COMPARISON: WHICH SHOULD YOU CHOOSE?

| Goal | What You Should Do | Difficulty | Time Required |
| :--- | :--- | :---: | :---: |
| **"I just want a live working link to submit to my supervisor right now"** | **Deploy ONLY to Vercel** (Import `web/soc-dashboard`) | Easiest | 2 minutes |
| **"I want the complete backend API, live server, and cron job in one place"** | **Deploy ONLY to Render** (Use Blueprint `render.yaml`) | Very Easy | 3 minutes |
| **"I want the ultimate full-grade architecture to impress my supervisor"** | **Deploy BOTH** (Render backend + Vercel frontend) | Easy | 5 minutes |

---

## 3. SCHEDULED CRON JOB (DOES IT REQUIRE A SERVER?)

AegisKernel has two independent cron job options:

1. **GitHub Actions Scheduled Cron (100% Free & Serverless):**
   - Configured in [`.github/workflows/scheduled_audit_cron.yml`](file:///d:/internship%20project%20%20soc/.github/workflows/scheduled_audit_cron.yml).
   - Runs automatically on GitHub's cloud runners every 6 hours (`0 */6 * * *`).
   - Requires **no active server** on Render or Vercel; GitHub executes the simulation, audits the cryptographic evidence vault, and logs the result automatically.
   - You can also manually trigger it anytime by clicking **Actions** $\to$ **AegisKernel Scheduled Threat-Hunting** $\to$ **Run workflow**.

2. **Render Cron Job:**
   - Pre-configured in [`render.yaml`](file:///d:/internship%20project%20%20soc/render.yaml) under `aegis-threat-hunt-cron`.
   - Runs on Render infrastructure alongside your backend.

---

## 4. VERIFICATION CHECKLIST FOR SUPERVISOR SUBMISSION

- [x] Code pushed to GitHub: `https://github.com/ManishPatil2005/AegisKernel`
- [x] Comprehensive Academic & Industry Report: [`docs/SUPERVISOR_FINAL_PROJECT_REPORT.md`](file:///d:/internship%20project%20%20soc/docs/SUPERVISOR_FINAL_PROJECT_REPORT.md)
- [x] 12-Member Board Audit Report: [`docs/FINAL_JOINT_REVIEW_BOARD_AUDIT.md`](file:///d:/internship%20project%20%20soc/docs/FINAL_JOINT_REVIEW_BOARD_AUDIT.md)
- [x] Vercel Configuration: [`vercel.json`](file:///d:/internship%20project%20%20soc/vercel.json) & [`web/soc-dashboard/vercel.json`](file:///d:/internship%20project%20%20soc/web/soc-dashboard/vercel.json)
- [x] Render Blueprint: [`render.yaml`](file:///d:/internship%20project%20%20soc/render.yaml)
- [x] Scheduled Automated Cron: [`.github/workflows/scheduled_audit_cron.yml`](file:///d:/internship%20project%20%20soc/.github/workflows/scheduled_audit_cron.yml)
