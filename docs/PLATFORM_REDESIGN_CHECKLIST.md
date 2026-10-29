# Sentinel AI platform audit and upgrade checklist

## Repository findings

- React 18, TypeScript, Vite, React Router, Tailwind, Vitest, React Testing Library, and Recharts are used by `frontend/`.
- FastAPI, Pydantic Settings, SQLAlchemy, Alembic, MySQL (`pymysql`), pytest, HTTPX, ReportLab, and `google-genai` are used by `backend/`.
- Frontend routes include public home, login, registration, OTP verification, dashboard, scan creation/history/details/comparison, findings/details, remediation, Defensive Guidance, assets, reports, verification, activity, and settings.
- Backend owns the current session/CSRF auth design, email and phone OTP challenges, bounded scanner, persisted scans/findings/assets, Gemini/local guidance, PDF/CSV export, activity records, and verification attempts.
- The `User` model has no role field or admin authorization model. No admin-only page or action was present; this upgrade does not invent one.
- Password reset/recovery, profile editing, registered-device/session listing, and notification preference storage were not present. Password change is now supported; reset/recovery and preferences remain unavailable.
- SMS support already included a provider switch, development-only console output, and a Twilio REST adapter. Real delivery still requires the account, sender configuration, geographic permissions, and a handset delivery check described in `backend/REAL_SMS_SETUP.md`.

## Implementation checklist

- [x] Apply a consistent midnight-blue/cyan command-center theme, accessible focus states, reduced-motion behavior, and responsive workspace navigation.
- [x] Add a public product landing page and retain the existing account verification gates.
- [x] Use the existing database records for dashboard totals, severity chart, recent scans, and activity; mark limited/incomplete source data clearly.
- [x] Add backend-filtered, paginated scan history and same-target scan comparison. Label missing later observations as “no longer observed,” not “fixed.”
- [x] Persist owner-scoped remediation status and transition history; write actor and timestamp; record activity and notifications.
- [x] Persist in-app notifications for scan completion, high/critical observations, reports, and remediation changes; support read state.
- [x] Record password, login, registration, OTP, scan, report/export, and remediation security events without storing credentials or codes in event messages.
- [x] Add owner-scoped PDF and formula-safe CSV export plus report metadata history.
- [x] Keep Gemini integration and evidence handling intact; retain the safe Markdown renderer and current-turn/history API behavior.
- [x] Keep Twilio isolated behind the current SMS provider selection; add send-rate counters keyed with HMAC, five-minute default OTP expiry, and account setup documentation.
- [x] Add regression coverage for platform API permissions/workflows, SMS request behavior, and password update.
- [ ] Configure a Twilio account/sender and confirm real delivery to a handset. Code tests do not prove carrier delivery.
- [ ] Apply Alembic migrations `20261027_0007` and `20261027_0008` to an existing database before using remediation, notifications, or persistent OTP send limits.
- [ ] Install/use Node.js to run the frontend test suite and production build in this environment.

## Data and operational notes

Migration `20261027_0007` adds remediation state/history and notifications. Migration `20261027_0008` adds keyed OTP send-attempt counters. Both have downgrade functions and do not delete existing application records. Apply them from `backend/` using the project virtual environment with `python -m alembic upgrade head` after confirming the configured database is backed up and available.

OTP rate counters store HMAC digests of recipient and client IP; expired rate rows are pruned during later send-limit checks. Existing audit/activity events are owner-filtered by the API, but the project has no configurable audit-retention policy yet.
