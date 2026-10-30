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
