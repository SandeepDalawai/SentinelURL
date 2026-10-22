# SentinelURL

Explainable suspicious URL analysis for local investigation. SentinelURL parses URL strings, runs transparent heuristic checks, assigns a capped risk score, and stores scans in a local SQLite database. It does not open or fetch submitted URLs.

## Problem and objectives

Links can disguise their destination with misleading subdomains, encoding, lookalike names, or unusual URL structure. SentinelURL helps a student, analyst, or general user inspect those visible signals and understand why they may deserve review. Its objectives are to validate links safely as text, explain each rule with evidence and a next step, preserve local scan history, and make limitations visible beside every result.

## Technology stack

- Frontend: React 18, TypeScript, Vite, React Router, Recharts, Lucide icons, and custom accessible CSS components.
- Backend: Python 3.11+, FastAPI, Pydantic, SQLAlchemy, and SQLite.
- Analysis: Python `urllib.parse`, `ipaddress`, IDNA support, bundled Public Suffix List data via `tldextract`, and configurable rule-based checks.
- Tests: Pytest and FastAPI TestClient / HTTPX.

## Architecture and workflow

The browser sends a URL to the local FastAPI service. The API validates and parses the string, normalizes the hostname, extracts the registered domain, runs deterministic detection rules, groups and scores the findings, then saves the analysis in SQLite. History, reports, charts, and CSV exports read from those saved records. Bulk CSV analysis uses the same engine and stores each successful row separately.

## Features

- React + TypeScript + Vite interface with dashboard, scan workspace, history, bulk CSV, analytics, and methodology pages.
- FastAPI service with versioned endpoints, SQLite persistence, pagination, deletion, summary analytics, and CSV bulk analysis.
- Modular URL feature extraction, configurable brand references, rule findings, evidence, recommendations, and severity-aware scoring.
- CSV reports safely guard spreadsheet formula injection. Bulk upload has file, row, and URL limits.
- No API keys, external reputation providers, live DNS/RDAP, PDF export, or ML model are required or currently implemented.

## Requirements

- Python 3.11+ (3.12 tested as the target runtime)
- Node.js 20+
- Windows 11 / VS Code or Linux

Python dependencies are pinned in `backend/requirements.txt`; npm dependencies are pinned by `frontend/package-lock.json` when generated via `npm install`.

## Windows setup

```powershell
cd outputs\sentinelurl
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r backend\requirements.txt
Copy-Item backend\.env.example backend\.env
```

Start the API in one terminal:

```powershell
cd backend
..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Start the UI in another:

```powershell
cd frontend
npm install
npm run dev
```

Open the Vite URL (normally `http://localhost:5173`). API docs are at `http://127.0.0.1:8000/docs`.

## Linux setup

```bash
cd outputs/sentinelurl
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r backend/requirements.txt
cp backend/.env.example backend/.env
```

In separate terminals, run `cd backend && ../.venv/bin/uvicorn app.main:app --reload` and `cd frontend && npm install && npm run dev`.

## Configuration

Copy `backend/.env.example` to `backend/.env`. Set `DATABASE_URL` to change the local SQLite path, `CORS_ORIGINS` to a comma-separated list of trusted UI origins, and `SENTINELURL_BRANDS` to customize comma-separated brand references. Defaults allow only localhost Vite origins. There are no provider secrets to configure. The `.env` file is ignored by Git. If the API runs at a different address, copy `frontend/.env.example` to `frontend/.env.local` and set `VITE_API_URL` before starting Vite.

## API

- `GET /api/v1/health`
- `POST /api/v1/scans` — `{ "url": "https://example.com/path" }`
- `GET /api/v1/scans?search=&severity=&start_date=&end_date=&sort_by=created_at&sort_order=desc&page=1&page_size=20`
- `GET /api/v1/scans/{scan_id}`
- `DELETE /api/v1/scans/{scan_id}`
- `POST /api/v1/scans/bulk` — multipart CSV; expects a `url` column or one URL per row
- `GET /api/v1/analytics/summary`
- `GET /api/v1/analytics/trends`
- `GET /api/v1/reports/export.csv`

## Detection and scoring

Rules assess structural signals such as URL length, subdomain count, credentials, IP literals, uncommon ports, query volume, encoding, punycode, suspicious brand placement, and lookalike domains. A signal is evidence for review and is not proof of maliciousness. Registered-domain logic uses `tldextract` with its bundled suffix data and no network suffix-list refresh. Findings are grouped to avoid stacking repeated signals: each rule contributes once, with a severity/reliability weight and a diminishing-return group aggregation; a strong signal can dominate, and the final heuristic score is capped at 100. Score bands (0–24 Low, 25–49 Medium, 50–74 High, 75–100 Critical) are engineering thresholds, not calibrated probabilities or validated security standards.

The brand reference list defaults to ten common names and can be customized with `SENTINELURL_BRANDS`. The ML classifier and SHAP are not implemented; no model or training data is included. Threat intelligence providers are also not implemented, so SentinelURL has no API-key setup and no URLs are shared externally.

## Data and security

Scans are stored in `backend/sentinelurl.db` by default until deleted. Do not enter URLs containing sensitive tokens if local retention is unsuitable. Delete individual records from History. Logs do not include full submitted URLs. SentinelURL never automatically visits, resolves, or submits URLs to third parties. HTTPS is not considered proof of legitimacy. Database files and `.env` are excluded from version control.

## Tests

From the project root: `python -m pytest backend/tests -q`. Tests use benign URLs and mocked dependencies only; they never visit live suspicious URLs.

## Demonstration workflow

1. Start the API and frontend using the commands above.
2. In Overview, scan `https://paypal.com.attacker.example/login` to see that the registered domain is `attacker.example` and inspect the brand-subdomain evidence.
3. Review the rule explanation, risk score, contributing signals, and limitations in the result report.
4. Search or filter that scan in History, then export a CSV report from Reports & analytics.
5. Upload a UTF-8 CSV with a `url` header to demonstrate batch analysis and per-row validation.

Use only benign demonstration URLs such as the reserved `.example` domain above.

## Screenshots

Add screenshots here after capturing the running application.

## Limitations and next steps

Heuristics produce review signals and can yield false positives or miss threats. There is no trained model, external reputation integration, DNS/RDAP inspection, PDF report, account system, or multi-user access control. SQLite is intended for local use. A future release could add consent-gated reputation adapters, opt-in DNS/RDAP with SSRF-safe resolvers, a vetted licensed dataset and reproducible ML training, PDF export, and database migrations.

## License

No project license has been selected. Third-party dependency licenses remain those of their respective authors; review them before redistribution. No dataset is included or used.
