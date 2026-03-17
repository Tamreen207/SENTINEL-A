# Sentinel-A: AI Agent Cyber Shield

Sentinel-A is a full-stack AI-powered cybersecurity SOC simulation platform that detects and responds to threats in near real time.

## Core Capabilities

- Threat Scanner for messages, emails, URLs, and system logs
- AI + rule-based detection for phishing, fraud, malicious URLs, suspicious commands, data tampering, and log deletion attempts
- Risk scoring engine (0-100) with Safe / Suspicious / High Risk classification
- Cyber attack simulation module with live alert generation
- Real-time alert history and SOC dashboard analytics
- Admin monitoring panel for high-risk filtering and trend review

## Project Structure

```
Sentinel-A/
├── backend/
│   ├── config/db.js
│   ├── controllers/
│   │   ├── adminController.js
│   │   ├── alertController.js
│   │   ├── dashboardController.js
│   │   ├── scanController.js
│   │   └── simulationController.js
│   ├── models/
│   │   ├── alertModel.js
│   │   └── scanResultModel.js
│   ├── routes/
│   │   ├── adminRoutes.js
│   │   ├── alertRoutes.js
│   │   ├── dashboardRoutes.js
│   │   ├── scanRoutes.js
│   │   └── simulationRoutes.js
│   ├── services/threatEngine.js
│   ├── .env.example
│   └── server.js
├── frontend/
│   ├── app/
│   │   ├── admin/page.tsx
│   │   ├── alerts/page.tsx
│   │   ├── dashboard/page.tsx
│   │   ├── scanner/page.tsx
│   │   ├── simulation/page.tsx
│   │   ├── layout.tsx
│   │   └── page.tsx
│   ├── src/services/api.ts
│   └── .env.example
└── README.md
```

## Database Collections

### scans

- inputData
- inputType
- riskScore
- classification
- detectedThreats
- highlightedKeywords
- explanation
- timestamp

### alerts

- alertType
- severity
- attackLocation
- message
- riskScore
- timestamp

## API Endpoints

- `POST /scan` – analyze suspicious input
- `POST /simulate/phishing` – phishing simulation
- `POST /simulate/data-attack` – unauthorized data tampering simulation
- `POST /simulate/log-delete` – log deletion simulation
- `POST /simulate/command-attack` – command injection simulation
- `GET /alerts` – alert history
- `GET /dashboard` – dashboard aggregate statistics
- `GET /admin/scans` – all scans
- `GET /admin/alerts` – all alerts
- `GET /admin/high-risk` – high-risk scan feed

## Local Setup

### Prerequisites

- Node.js 18+
- MongoDB Atlas cluster (or local MongoDB)

### 1) Backend Setup

```bash
cd backend
cp .env.example .env
npm install
npm start
```

Backend runs on `http://localhost:5000`.

### 2) Frontend Setup

```bash
cd frontend
cp .env.example .env.local
npm install
npm run dev
```

Frontend runs on `http://localhost:3000`.

## Run in Production Mode Locally

```bash
cd frontend
npm run build
npm start
```

## Example Inputs for Demo

### Phishing / Fraud (High Risk)

```text
URGENT: Your bank account is suspended. Verify OTP now at http://bit.ly/secure-verify-login
```

### Suspicious Command

```text
sudo rm -rf /var/log && truncate -s 0 /var/log/auth.log
```

### Data Manipulation

```text
UPDATE users SET balance = 999999 WHERE id = 1; unauthorized change requested
```

### Safe Input

```text
Team sync moved to 3 PM. Please review the sprint board updates.
```

## Attack Simulation Demo Flow

1. Open `Attack Simulation` page.
2. Click `Simulate Data Manipulation`.
3. Observe changed data from `Server Status: OK` to `Server Status: HACKED`.
4. Open `Alerts` and `Dashboard` pages.
5. Show generated red alert with threat type, risk score, location, and timestamp.

## Deploy to GitHub

```bash
git init
git add .
git commit -m "Sentinel-A full-stack SOC implementation"
git branch -M main
git remote add origin https://github.com/<your-username>/sentinel-a.git
git push -u origin main
```

## Deploy Frontend to Vercel

1. Import `frontend` directory as a Vercel project.
2. Framework preset: Next.js.
3. Add env var:
	- `NEXT_PUBLIC_API_BASE_URL=https://<your-render-backend>.onrender.com`
4. Deploy.

## Deploy Backend to Render

1. Create new Web Service from your GitHub repo.
2. Root directory: `backend`
3. Build command: `npm install`
4. Start command: `npm start`
5. Add env vars:
	- `PORT=5000`
	- `MONGO_URI=<mongodb-atlas-uri>`
	- `FRONTEND_ORIGIN=https://<your-vercel-domain>`
6. Deploy and copy Render URL.

## MongoDB Atlas Setup

1. Create cluster and database user.
2. Allow Render/Vercel IP access (or temporary `0.0.0.0/0` for demo).
3. Copy connection URI into backend `MONGO_URI`.

## Notes

- If `3000` is in use: stop previous Next.js process before restart.
- If backend fails to connect: verify `MONGO_URI` and Atlas network access.
- Legacy endpoint `POST /check` is mapped to scanner logic for compatibility.
