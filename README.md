# Sentinel AI

Detect. Analyze. Resolve. Verify. Secure.

Sentinel AI is an AI-assisted website security assessment and remediation platform. Phase 1 provides a bounded, evidence-based HTTP(S) assessment workflow. It does **not** claim that a target is secure, fabricate scan results, execute target code, exploit vulnerabilities, or perform arbitrary URL fetching.

## Stack and supported local runtimes

- Frontend: React 18, TypeScript, Vite 6, Tailwind CSS, React Router, Recharts, Lucide React
- Backend: Python 3.11+, FastAPI, Uvicorn, Pydantic Settings, SQLAlchemy, Alembic
- Tests: Pytest, Vitest, React Testing Library
- Local application database: MySQL through XAMPP (PyMySQL). SQLite is used by isolated test fixtures; the full clean Alembic chain currently has MySQL-specific operations and is not a supported SQLite initialization path.
- Recommended Windows JavaScript runtime: current Node.js LTS, which includes npm. Install it from the [official Node.js download page](https://nodejs.org/en/download/).

The backend supports Python 3.11 and newer compatible Python 3 releases. Python 3.11.9 was verified in this environment with OpenSSL 3.0.13. Use a normal CPython installation with working SSL support; do not modify the managed Python installation supplied by an editor or system tool.

## Windows PowerShell setup

Run these commands from the repository root, `C:\xampp\htdocs\isproject`.

### 1. Configure the backend

```powershell
Set-Location .\backend
if (-not (Test-Path ..\.venv311\Scripts\python.exe)) { py -3.11 -m venv ..\.venv311 }
..\.venv311\Scripts\python.exe -m pip install -r requirements.txt
if (-not (Test-Path .env)) { Copy-Item .env.example .env } else { Write-Host "backend/.env already exists; leaving it unchanged." }
```

If PowerShell blocks activation for the current user, run PowerShell as the same user and use:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

The `.env` file is local-only. Configure it in a local editor and do not paste its contents into logs, tickets, or chat:

```dotenv
APP_ENV=development
DATABASE_URL=mysql+pymysql://root:@127.0.0.1:3306/sentinel_ai
API_V1_PREFIX=/api/v1
ALLOWED_ORIGINS=http://localhost:5173,http://localhost:5174,http://localhost:5175
AI_PROVIDER=none
AI_API_KEY=
GEMINI_API_KEY=
AI_BASE_URL=https://api.openai.com/v1
AI_MODEL=gemini-3.5-flash-lite
AI_TIMEOUT_SECONDS=30
AI_MAX_INPUT_CHARS=12000
AI_MAX_OUTPUT_CHARS=5000
AI_REQUESTS_PER_MINUTE=10
SESSION_TTL_MINUTES=60
AUTH_COOKIE_SECURE=false
```

For the XAMPP defaults, start the MySQL module in the XAMPP Control Panel and create a database named `sentinel_ai` in phpMyAdmin. The local XAMPP root account commonly has an empty password; if yours has a password, URL-encode it and update only your local `backend/.env` value. Never commit real credentials.

`AI_PROVIDER=none` keeps the assistant in an honest setup state. For Gemini, set `AI_PROVIDER=gemini`, `GEMINI_API_KEY`, and an `AI_MODEL` currently enabled for your Google AI API account. For OpenAI-compatible providers, set `AI_PROVIDER=openai` or `openai_compatible`, `AI_API_KEY`, `AI_BASE_URL`, and `AI_MODEL`. Keep provider keys in `backend/.env`; they are not sent to the browser or written to application logs. Settings load from `backend/.env` and are cached for the life of the process, so restart FastAPI after changing provider configuration. Process environment variables take precedence over values in the file. Requests are bounded by `AI_TIMEOUT_SECONDS`, the configured input/output limits, and a process-local per-user request limit; multi-worker deployments should replace that limiter with a shared store.

### 2. Verify the database without modifying it

Start the MySQL module in the XAMPP Control Panel. In phpMyAdmin, the read-only query `SELECT VERSION() AS server_version, DATABASE() AS current_database;` confirms the selected server and schema. From `backend/`, inspect Alembic status:

```powershell
..\.venv311\Scripts\python.exe -m alembic current
..\.venv311\Scripts\python.exe -m alembic heads
```

The existing Sentinel AI database in the verified development environment is at `20261028_0009 (head)`, so it needs no migration. If `current` and `heads` differ, stop and review the exact pending migration, take and verify a protected backup, and schedule the migration separately. Never run `alembic upgrade head` as a startup step against an existing database. For a new disposable MySQL schema, configure a separate local database URL and apply migrations only after confirming that it points to that new schema. Do not overwrite `backend/.env` to switch between databases.

### 3. Start FastAPI

```powershell
..\.venv311\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8001
```

Expected local URLs:

- API health: http://127.0.0.1:8001/api/v1/health
- Swagger UI: http://127.0.0.1:8001/docs
- OpenAPI JSON: http://127.0.0.1:8001/openapi.json

The health response should be `{"status":"ok","service":"Sentinel AI"}`. It verifies database connectivity with `SELECT 1`; it is not a schema/migration readiness probe. Check Alembic current/head separately before demonstration or deployment. Registration requires both email and mobile OTP delivery. Set a long random `OTP_PEPPER`, configure a real SMTP provider (`EMAIL_PROVIDER=smtp`, `SMTP_HOST`, `SMTP_FROM`, and any required SMTP credentials), and select a mobile provider in local-only `backend/.env`. TextBee setup uses `SMS_PROVIDER=textbee`, `TEXTBEE_ENABLED=true`, and `TEXTBEE_API_KEY`; it requires an online, enabled Android gateway device. See [TextBee setup](backend/TEXTBEE_SETUP.md). Twilio uses `SMS_PROVIDER=twilio`, `SMS_ACCOUNT_SID`, `SMS_AUTH_TOKEN`, and `SMS_FROM_NUMBER`. The development console provider (`SMS_PROVIDER=console`) is accepted only with `APP_ENV=development`; it writes the mobile OTP only to the dedicated local backend logger, never to an API response or frontend. Email OTP delivery remains SMTP. Provider-unavailable and failed delivery are reported; there is no cross-provider fallback. OTPs are stored only as hashes; passwords are stored as salted scrypt hashes; and sessions use HttpOnly cookies plus a separate CSRF cookie. In production, set `APP_ENV=production` and use HTTPS so secure cookies are enabled. `AUTH_COOKIE_SECURE=false` is only for local HTTP development. Email sender display names are set to `Sentinel AI` while retaining the configured `SMTP_FROM` address; the provider must permit that verified sender identity.

For zero-cost local mobile OTP testing, edit `backend\.env` without committing it and use values equivalent to:

```dotenv
APP_ENV=development
OTP_PEPPER=<long-random-secret>
EMAIL_PROVIDER=smtp
SMTP_HOST=<your-smtp-host>
SMTP_PORT=587
SMTP_USERNAME=<your-smtp-username>
SMTP_PASSWORD=<your-smtp-app-password>
SMTP_FROM=<your-sender>
SMS_PROVIDER=console
```

Start the backend from `C:\xampp\htdocs\isproject\backend`; the mobile code appears only in that backend terminal under the dedicated development logger. Never use this provider outside local development and never copy real credentials into `.env.example` or source control.

### 4. Install and start the frontend

Open a second PowerShell window at the repository root:

```powershell
Set-Location .\frontend
# On this workstation Node is installed at D:\; this affects only this shell.
$env:Path = "D:\;$env:Path"
if (-not (Test-Path .env)) { Copy-Item .env.example .env } else { Write-Host "frontend/.env already exists; leaving it unchanged." }
npm.cmd ci
npm.cmd run dev
```

The Vite development server starts at http://localhost:5173 and tries the next port when one is occupied (for example, 5174 or 5175). The supplied `VITE_API_BASE_URL=/api/v1` sends requests through the Vite proxy to FastAPI at `http://127.0.0.1:8001`; this keeps browser API calls same-origin in local development. If you configure the frontend to call FastAPI directly, set `ALLOWED_ORIGINS` in `backend/.env` to the exact frontend origin. The example includes ports 5173, 5174, and 5175.

### 5. Run automated checks

Backend, from `backend/` with the root `.venv311` active:

```powershell
python -m pytest -q
python -m compileall -q app tests
```

Frontend, from `frontend/` after `npm ci`:

```powershell
npm.cmd test
npm.cmd run build
```

The committed `package-lock.json` supports `npm ci` for repeatable frontend installs. Backend `requirements.txt` uses bounded version ranges rather than a fully resolved lockfile; deployments should qualify and pin a backend lock against their target OS/Python version before release.

### 6. Run isolated browser smoke tests

The optional Playwright suite uses the installed Windows Chrome executable (override with `CHROME_EXECUTABLE` if needed), the repository `.venv311`, and temporary ports 18081 and 15173. It refuses to reuse existing servers. It creates a disposable SQLite database and a randomly passworded, already-verified test account in the system temporary directory; it does not read or migrate the configured MySQL database, send OTPs, call an AI provider, or scan a website. Test data and traces are removed after a normal run.

```powershell
Set-Location .\frontend
npm.cmd run test:e2e
```

The browser checks public landing/auth navigation, invalid login, a seeded isolated login and dashboard, dashboard API failure/retry, logout/protected routing, and the provider-unavailable Assistant state. These tests do not verify live OTP delivery, a paid provider call, scanner network behavior, or production ingress. If either temporary port is occupied, the suite fails instead of connecting to an existing application.

Type-check the Playwright configuration and specs with `npm.cmd run typecheck:e2e`. Stop both local servers with Ctrl+C in their own terminal windows when finished. The MySQL service can remain running; no database cleanup is needed.

### Local demonstration checklist

1. Start XAMPP MySQL; verify the intended schema in phpMyAdmin without changing it.
2. Run `alembic current` and `alembic heads` from `backend/`. Continue only when the expected existing schema is at head; do not upgrade/reset it as a demo setup step.
3. Start FastAPI on `127.0.0.1:8001` and confirm `/api/v1/health` reports success.
4. Start Vite on `localhost:5173`, open the landing page, then sign in with an existing verified account. Do not create a test account in the existing MySQL schema.
5. For scans, choose only a target you are authorized to assess. Review check coverage, incomplete/failure messages, saved findings, and report output.
6. Live registration requires configured SMTP and mobile OTP delivery. Without both, use the isolated browser smoke suite rather than weakening verification.
7. AI works in local evidence-only mode with `AI_PROVIDER=none`. A live provider call requires backend-only `AI_PROVIDER=gemini`, `GEMINI_API_KEY`, and an account-enabled `AI_MODEL`; restart FastAPI after changing them. Do not put provider keys in frontend environment files.

## If Node.js or npm is missing

1. Open the [official Node.js download page](https://nodejs.org/en/download/).
2. Select the current **LTS** Windows installer for your machine, normally Windows x64.
3. Run the `.msi` installer with the default npm and PATH options enabled.
4. Close and reopen PowerShell, then verify:

```powershell
node --version
npm --version
```

5. Return to `frontend/` and run `npm install`, `npm test`, and `npm run build`.

Do not use the Node.js “Current” release for the project unless you intentionally want to test against a non-LTS runtime. The Vite 6 configuration is compatible with supported modern Node.js LTS releases.

## Troubleshooting

- `python` resolves to the Microsoft Store alias: use `py -3.11` or install CPython from python.org, then recreate `.venv`.
- `Activate.ps1` is blocked: use the execution-policy command above, or invoke tools directly with `..\.venv311\Scripts\python.exe` from `backend`.
- `alembic upgrade head` cannot find the app: confirm the current directory is `backend` and the `.venv311` virtual environment is active.
- `The configured database is unavailable`: confirm XAMPP MySQL is running, the `sentinel_ai` database exists, and the local `DATABASE_URL` has the correct username, password, host, port, and driver (`mysql+pymysql`).
- CORS errors in the browser: confirm FastAPI is running on port 8001 and `ALLOWED_ORIGINS` includes the exact Vite URL.
- Dependency installation fails with SSL errors: use a regular CPython installation with working `ssl` support and network access. Do not modify a managed interpreter that lacks SSL.
- Port conflicts: start Uvicorn with `--port 8001`; if an existing development process is using the port, restart that process after changing `.env`.

## Phase 1 scanner behavior

Start an authorized assessment from `http://localhost:5173/scans/new`. The backend validates and normalizes the URL, resolves every hostname, rejects loopback/private/link-local/reserved/metadata addresses, pins requests to validated IPs to reduce DNS-rebinding risk, and revalidates every redirect. Requests use a 10-second timeout, a 2 MiB response limit, at most three redirects, and a global four-request concurrency limit.

The scanner reports observable HTTPS/TLS, redirect, security-header, cookie-attribute, and DNS results. A missing header is reported as a configuration observation rather than proof of exploitability. Checks that cannot complete are recorded as informational scan-limit findings. No AI provider is used to generate findings or scores.

Risk scoring is deterministic: critical=40, high=25, medium=15, low=5, and info=0 points per unique logical finding, capped at 100. Score bands are none (0), low (1–14), medium (15–39), high (40–69), and critical (70–100). The score summarizes accumulated bounded observations; it is not a percentage of security and is not a guarantee that the target is secure. Repeated execution of a scan is idempotent for its logical findings.

The primary API endpoints are:

- `POST /api/v1/scans` with `{"target_url":"https://authorized.example"}` to create a background assessment.
- `GET /api/v1/scans` to list recent assessments.
- `GET /api/v1/scans/{id}` to retrieve status, score, redirects, check coverage, findings, structured evidence, and remediation. Scan statuses are `pending`, `running`, `completed`, `partial`, or `failed`; partial results disclose checks that were skipped or inconclusive.
- `GET /api/v1/scans/{id}/report.pdf` to generate a non-persistent PDF from the saved scan.
- `POST /api/v1/findings/{finding_id}/verification` to queue a safe verification attempt and `GET` the same path to review its history. A missing later observation is inconclusive, not proof of remediation.
- `GET /api/v1/activity` to retrieve persisted application events with bounded pagination.
- `GET /api/v1/assets` and `POST /api/v1/assets` to list/register normalized authorized assets.
- `GET /api/v1/health` to verify the configured database and service.

Authentication endpoints are `POST /api/v1/auth/register`, `POST /api/v1/auth/verify-otp`, `POST /api/v1/auth/resend-otp`, `POST /api/v1/auth/login`, `POST /api/v1/auth/logout`, and `GET /api/v1/auth/me`. Registration returns a short-lived opaque verification token, not either OTP. A session is created only after both channels verify. Resource endpoints require an authenticated session and mutating requests require the CSRF token issued in the readable CSRF cookie. The login limiter is process-local, so deployments with multiple workers should add a shared rate-limit store before production use.

The authenticated AI endpoints are `GET /api/v1/assistant/status` and `POST /api/v1/assistant/query`. The assistant is disabled honestly when no provider is configured. When enabled, it uses only the selected user's persisted scan/finding context, treats that context as untrusted data, bounds input/output and timeout, and provides defensive explanations only. It does not scan targets, execute commands, exploit findings, or persist conversations.

Migration `20261027_0005` adds users, sessions, and nullable ownership fields. Existing scans, assets, and activity rows are intentionally preserved with no guessed owner and are therefore not exposed to registered users. An administrator must perform an explicit, reviewed ownership backfill if historical records need to be assigned.

## Architecture and security scope

The backend separates API routes, configuration, persistence, schemas, services, scanning policy, risk classification, AI integrations, and reporting. The scanner boundary is policy-driven and keeps SSRF protections, redirect revalidation, timeouts, response limits, and concurrency limits close to the network client.

The frontend is organized by layout, reusable components, pages, API client, types, and styling tokens. All displayed scan metrics and findings come from real API data; the empty dashboard state is used when no scans exist.

Only assess websites you are authorized to assess. The scanner rejects loopback, private, link-local, reserved, and cloud metadata destinations; validates DNS and redirects; enforces response/body/time limits; and applies concurrency controls. It does not guarantee protection from every network-layer or application-layer race, and it does not assess authenticated application behavior. Exploitation, destructive testing, and automatic production changes are out of scope.

