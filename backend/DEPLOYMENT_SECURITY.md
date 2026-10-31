# Production transport and login throttling

## HTTPS and trusted proxies

In `APP_ENV=production`, the ASGI app redirects HTTP requests to HTTPS and adds
`Strict-Transport-Security: max-age=31536000` to HTTPS responses. Auth cookies
are also marked Secure. HSTS is sent only when the effective ASGI request scheme
is HTTPS.

Set these backend environment values in production:

- `APP_ENV=production` (enables the redirect and HSTS middleware and Secure auth cookies).
- `ALLOWED_ORIGINS=https://<application-host>` (comma-separated HTTPS origins when there is more than one).
- `TRUSTED_PROXY_HOSTS=<proxy-ip-or-cidr>` when TLS terminates at a proxy. It defaults to loopback and rejects wildcard or non-IP entries in production.
- `DATABASE_URL=<existing MySQL connection URL>` and apply the reviewed Alembic head during the controlled migration window.
- `DATABASE_SSL_CA_PATH=<absolute path to a readable CA PEM file>` for TiDB Cloud. The application passes this to PyMySQL with both certificate and hostname verification enabled; TiDB Cloud hostnames are rejected at startup unless this value is set.
- `DATABASE_CONNECT_TIMEOUT_SECONDS=10` bounds MySQL/TiDB connect, read, and write waits; keep it between 1 and 60.
- `AUTH_COOKIE_SECURE` may be omitted; production forces Secure cookies. Explicitly setting it to `false` prevents production startup.

The Procfile and Nixpacks start phase run only Uvicorn; they never run migrations.
EthioDeploy must not configure a migration command as an image-build command.
Run the guarded migration only once in a runtime release/job environment after
confirming the target and current revision:
`python -m app.migration_release --confirm-production-target`.
It refuses every target except the approved TiDB host/database and refuses every
current revision except `20261028_0009`; it only advances to `20261030_0010`.
It never downgrades, stamps, resets, or deletes data.

The production operations commands are separate from the web start command:

```text
python -m app.production_db_ops diagnose --confirm-production-target
python -m app.production_db_ops verify-schema --confirm-production-target
python -m app.production_db_ops migrate --confirm-production-target
python -m app.production_db_ops verify --confirm-production-target
```

Run `diagnose` and `verify-schema` first, review their exit status and output,
and run `migrate` only once from a controlled runtime job. These commands
reject unexpected host, port, database, or TiDB TLS settings and never print
credentials. `migrate` uses a database advisory lock and refuses unexpected
Alembic revisions; it is not an image-build command.

## First-time empty production initialization

The ordinary guarded migration intentionally refuses an empty schema. For a
new, verified production database only, use this separate manual command from
a controlled runtime job after explicit approval:

```text
python -m app.migration_release --confirm-production-target --initialize-empty-production
```

The runtime must provide `DATABASE_URL` resolving exactly to the approved TiDB
host, port, and `sentinel_ai` database, plus a readable
`DATABASE_SSL_CA_PATH`. The application must pass both TLS certificate and
hostname verification; `DATABASE_CONNECT_TIMEOUT_SECONDS` remains bounded by
normal settings validation. The command never prints the URL or any
credential.

Before invoking Alembic, the initializer acquires the existing migration
advisory lock and verifies `SELECT DATABASE()` is `sentinel_ai`, then inspects
all tables and views and checks Alembic heads. It refuses any existing table,
view, or revision, including `alembic_version`. It then runs the real Alembic
upgrade chain from base through `20261030_0010`; it does not stamp a revision
and never runs automatically during image builds, release startup, or web
worker startup.

Preparation and recovery requirements:

1. Obtain an approved consistent backup and verify it can be restored to an
   isolated database. Record the backup location and checksum without putting
   credentials in command arguments or logs.
2. Confirm the target identity and empty-schema results with read-only SQL and
   obtain explicit approval for initialization.
3. Run the command once from a single controlled runtime process. Do not run
   it concurrently with another migration or application deployment.
4. Verify `20261030_0010`, all required tables, indexes, and the server-reported
   database identity with `production_db_ops verify` and the protected
   diagnostic flow.
5. If Alembic reports a failure, stop. The initializer performs no destructive
   cleanup; MySQL-compatible DDL may be non-transactional. Inspect the actual
   tables and revision before any retry, preserve the partial state, and obtain
   a reviewed repair plan. Never drop, truncate, recreate, downgrade, or stamp
   to bypass the failure.

## Temporary read-only diagnostic endpoint

The HTTP diagnostic flow is disabled by default. To enable it temporarily in
EthioDeploy, set `ADMIN_DIAGNOSTICS_ENABLED=true` and provide a high-entropy
`ADMIN_DIAGNOSTIC_SECRET` of at least 32 characters through protected runtime
environment variables. Do not put this secret in the frontend, URL, source
code, or logs. The administrator must authenticate and pass CSRF validation,
then make these two POST requests from a controlled client:

```text
POST /api/v1/admin/database-diagnostics/challenge
X-Sentinel-Diagnostic-Secret: <protected secret>
X-CSRF-Token: <authenticated session CSRF token>

POST /api/v1/admin/database-diagnostics
X-CSRF-Token: <authenticated session CSRF token>
{"challenge":"<one-time challenge response>"}
```

The challenge is single-use, expires after `ADMIN_DIAGNOSTIC_CHALLENGE_TTL_SECONDS`
(default 60), and is rate-limited by client address using
`ADMIN_DIAGNOSTIC_RATE_LIMIT` (default 5 attempts per 15 minutes). The response
contains only database identity metadata, TLS verification flags, revisions,
table existence, row counts, and schema issue categories. Disable the feature
again immediately after diagnosis.

## Local-to-TiDB import workflow

The import utility is dry-run first and rejects unexpected targets, missing
TLS verification, missing backups, non-empty destinations, revision mismatch,
schema issues, duplicate/conflicting state, and orphaned relationships:

```text
python -m app.production_import plan --confirm-production-target --backup-path <protected-backup-path> --backup-sha256 <backup-sha256>
python -m app.production_import import --confirm-production-target --backup-path <protected-backup-path> --backup-sha256 <backup-sha256> --execute --confirm-import
```

`IMPORT_SOURCE_DATABASE_URL` must be provided only to the controlled import
runtime and is never printed. The default import excludes sessions, OTP
challenges, password-reset challenges, OTP send attempts, and temporary login
attempts because importing active or expired authentication state requires a
separate security review. It preserves primary keys, timestamps, ownership,
and application records for the explicitly listed import tables. The import
uses batches and a database advisory lock; it never runs automatically at web
startup or during image construction.

If TLS terminates at a reverse proxy, configure `TRUSTED_PROXY_HOSTS` with only
the proxy's actual source IP address(es) or CIDR ranges. The default trusts only
loopback. The proxy must overwrite (not append to client-supplied values for)
`X-Forwarded-Proto` and `X-Forwarded-For`, and the backend port must not be
reachable directly from untrusted networks. Run Uvicorn with its own proxy
header handling disabled so that the application applies the explicit trusted
proxy list exactly once:

```powershell
uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers
```

For a proxy on another host/container, set `TRUSTED_PROXY_HOSTS` to its private
address or narrow subnet. Do not use `*`. HSTS is a browser policy and does not
replace TLS configuration at the public ingress; enable HSTS there too if the
deployment has additional HTTPS-only hosts or needs `includeSubDomains`.

## TiDB Cloud TLS

Deploy the TiDB CA PEM as a readable file in the application image or through
the platform's protected file mechanism, then set `DATABASE_SSL_CA_PATH` to its
absolute path. Do not put the PEM contents in `DATABASE_URL`, disable certificate
verification, or use a URL option that bypasses hostname verification. The
Nixpacks configuration does not download or create this CA file, so the hosting
deployment must provide it before the backend starts.

For other MySQL providers, including an EthioDeploy MySQL add-on, the code does
not require a custom CA merely because the URL uses MySQL. `DATABASE_SSL_CA_PATH`
is optional unless the provider supplies a CA that must be configured. If it is
set, it must point to a readable certificate and PyMySQL receives both
certificate and hostname verification. EthioDeploy's public add-on
documentation confirms an internal managed MySQL 8 instance and automatic
`DATABASE_URL` injection, but does not document a custom CA filename or a
provider-specific TLS requirement; do not reuse a TiDB CA without confirming it
with EthioDeploy.

## Failed-login throttling

Failed-login events are stored in the configured application database under
HMAC-SHA-256 digests for the account, client address, and account/address pair
when `OTP_PEPPER` is configured; legacy configurations without it use SHA-256
digests. A
single InnoDB mutex row serializes only the short admission and finalization
transactions; password hashing runs outside that lock. In-flight attempts count
against the five-attempt limit, and successful authentication releases its
reservation. This provides a strict admission limit across workers using the
same migrated database without Redis. The shared mutex is a throughput
bottleneck under very high login volume and should be load-tested before scaling
to many workers.

A new database must be migrated to Alembic head (`20261030_0010`) before
deploying this code. The `20261028_0009` migration creates two tables and one
mutex row; it does not alter existing account or scan rows. Expired events are removed during
admission while the mutex is held. If a worker exits with an in-flight event,
the event expires after ten minutes.

## Applying `20261028_0009` to an existing MySQL database

This migration has been verified against an isolated MariaDB 10.4.32 instance;
the configured application database has not been migrated. Before applying it
to that database:

1. Confirm the application is at `20261027_0008` with `python -m alembic current`.
2. Take a consistent MySQL backup using the deployment's approved credential
   mechanism (for example, a protected option file or managed backup service).
   For an InnoDB database, a typical command is
   `mysqldump --defaults-extra-file=<protected-client-option-file> --single-transaction --routines --triggers <database> > <secure-backup-path>`.
   Verify that the backup can be restored to an isolated database before the
   production change window. Never put a password directly on the command line.
3. Apply `python -m alembic upgrade 20261028_0009` once, with the existing
   `DATABASE_URL` provided to the backend process. Do not print the environment
   or database URL while diagnosing failures.
4. Confirm `python -m alembic current` reports `20261028_0009`, then inspect
   `SHOW CREATE TABLE login_attempts`, `SHOW CREATE TABLE login_rate_limit_mutex`,
   and confirm the mutex contains exactly the row with `id=1`.
5. Start the updated application only after the schema checks pass.

MySQL/MariaDB DDL can implicitly commit, so a failed upgrade is not guaranteed
to roll back atomically. Inspect table and index state before any retry; do not
drop or recreate the application database. Prefer rolling the application
binary back while leaving these additive tables in place. Explicitly downgrading
`20261028_0009` drops the new rate-limit tables and loses their short-lived
throttle history, although it does not remove account, scan, or finding data.
