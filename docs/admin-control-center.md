# Admin Control Center

## Assigning administrator access

Administrator access is controlled by the backend deployment environment variable `ADMIN_USER_IDS`. It accepts comma-separated, positive user IDs. There is intentionally no API or UI action for granting administrator access.

1. Identify the intended existing account using a read-only account lookup in the approved database operations environment, for example `SELECT id, email FROM users WHERE email = 'authorized-account@example.test';`. Do not use the admin console to promote users.
2. Set `ADMIN_USER_IDS` in the backend process/service environment to the approved ID or IDs. Do not place credentials in this setting.
3. Restart the backend so its settings are reloaded, then sign in as the configured account. Its `/auth/me` response will include `is_admin: true` and the navigation will show Admin Control Center.
4. Confirm backend access is enforced by opening `/api/v1/admin/overview`; only allowlisted, authenticated accounts may access it.

Remove an ID from the deployment environment and restart the backend to revoke its administrator access. Account status changes and session revocation do not grant administrator access. Configured administrator accounts cannot be disabled from this console, and the current administrator cannot disable itself.

## High-impact account actions

Disabling an account revokes its active sessions. Enabling an account does not restore old sessions. Disabling, enabling, and session revocation require the administrator's current password, a CSRF-protected request, and create an `admin.*` activity event. Passwords are not recorded.

## Operational data limitations

- Service health reports backend/database reachability and whether AI, email, and SMS settings are configured. It does not perform outbound provider connectivity checks.
- Provider errors, AI request/latency/cost usage, and background-job queue state are not persisted by this installation; the console does not fabricate them.
- Login failure counters appear only when the database has the `login_attempts` table from Alembic revision `20261028_0009`.
- No automated backup registry, maintenance mode, role table, or password-recovery workflow exists in the current application.
- The configured database reported `20261028_0009 (head)` on 2026-10-29 via read-only Alembic inspection. The Admin Control Center did not apply migrations.
