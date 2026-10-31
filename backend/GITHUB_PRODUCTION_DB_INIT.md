# GitHub Actions production database initialization

The workflow at `.github/workflows/initialize-production-db.yml` is the only
supported GitHub Actions path for first-time production initialization. It has
`workflow_dispatch` only and is not called by push, pull request, deployment,
or scheduled workflows.

## Configure the protected environment

In the GitHub repository:

1. Open **Settings → Environments → New environment**.
2. Create the environment with the exact name `production-db-init`.
3. Under **Environment protection rules**, enable **Required reviewers** and
   select the people who must approve a production schema initialization.
4. Do not enable bypasses for administrators unless that is part of the
   approved production change policy.
5. Add these environment secrets to `production-db-init`:

   - `DATABASE_URL`: the protected TiDB connection URL. Never place it in YAML,
     repository variables, logs, or issue comments.
   - `DATABASE_SSL_CA_PATH`: a simple filename such as `tidb-ca.pem`. The
     workflow materializes the certificate only under the ephemeral runner
     temporary directory; directory paths and traversal components are refused.
   - `TIDB_CA_PEM`: the TiDB CA PEM contents. Store it only as the protected
     environment secret; never commit it or print it.

The workflow validates that the URL resolves to the reviewed TiDB host, port
`4000`, and database `sentinel_ai`. It also requires CA-backed certificate and
hostname verification. No secret values are echoed.

## What the workflow does

After GitHub grants the environment approval, the job:

1. Checks out the reviewed repository code.
2. Uses pinned Python `3.11.9`, compatible with `.venv311`.
3. Installs `backend/requirements.txt`.
4. Materializes the protected CA file with restrictive permissions.
5. Performs a read-only target and empty-schema preflight.
6. Runs only:

   ```text
   python -m app.migration_release --confirm-production-target --initialize-empty-production
   ```

The initializer rechecks the target while holding the migration advisory lock,
rejects every existing table or view and every existing Alembic revision, then
runs the complete chain to `20261030_0010`. It never stamps, drops, truncates,
resets, recreates, or cleans up after a failure. MySQL-compatible DDL may be
non-transactional; if a migration fails, stop and inspect the resulting state
with read-only diagnostics before any retry.

The workflow has a 15-minute timeout and a concurrency group that prevents two
initialization runs from executing simultaneously. It does not modify normal
deployment workflows.

## Manual execution

1. Confirm the target database backup and the read-only empty-schema evidence.
2. Open **Actions → Initialize empty production database**.
3. Select **Run workflow** on the reviewed branch/commit.
4. Review and approve the `production-db-init` environment gate.
5. Monitor the job without copying secrets or logs containing protected values.
6. After success, run the protected read-only diagnostic and verify the
   Alembic head is `20261030_0010` and all required tables/indexes exist.

Do not rerun after a failure until the database state has been reviewed. Do not
run the ordinary parent-only migration command against an empty schema.
