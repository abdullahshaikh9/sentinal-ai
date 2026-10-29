import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const frontendDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const projectDir = resolve(frontendDir, "..");
const tempParent = resolve(tmpdir());
const tempDir = mkdtempSync(join(tempParent, "sentinel-ai-e2e-"));
const databaseFile = join(tempDir, "browser-test.sqlite3");
const password = randomBytes(32).toString("base64url");
const email = "browser-test@example.test";
const databaseUrl = `sqlite:///${databaseFile.replaceAll("\\", "/")}`;

// Override backend secrets from both the parent process and backend/.env.
// The application and browser tests receive no real provider or OTP credentials.
const env = {
  ...process.env,
  DATABASE_URL: databaseUrl,
  APP_ENV: "development",
  ALLOWED_ORIGINS: "http://127.0.0.1:15173",
  TRUSTED_PROXY_HOSTS: "127.0.0.1",
  AUTH_COOKIE_SECURE: "false",
  AI_PROVIDER: "none",
  AI_API_KEY: "",
  GEMINI_API_KEY: "",
  AI_MODEL: "e2e-no-provider",
  OTP_PEPPER: randomBytes(32).toString("hex"),
  EMAIL_PROVIDER: "none",
  SMTP_HOST: "",
  SMTP_USERNAME: "",
  SMTP_PASSWORD: "",
  SMTP_FROM: "",
  SMS_PROVIDER: "none",
  SMS_ACCOUNT_SID: "",
  SMS_AUTH_TOKEN: "",
  SMS_FROM_NUMBER: "",
  TEXTBEE_ENABLED: "false",
  TEXTBEE_API_KEY: "",
  ADMIN_USER_IDS: "",
  SENTINEL_E2E_EMAIL: email,
  SENTINEL_E2E_PASSWORD: password,
  SENTINEL_E2E_OUTPUT_DIR: join(tempDir, "playwright-output"),
  VITE_API_BASE_URL: "http://127.0.0.1:18081/api/v1",
};

const python = resolve(projectDir, ".venv311", "Scripts", "python.exe");
const prepare = spawnSync(python, [join(frontendDir, "e2e", "prepare_database.py")], {
  cwd: projectDir,
  env,
  stdio: "inherit",
  timeout: 120_000,
});

let exitCode = prepare.status ?? 1;
if (!prepare.error && prepare.status === 0) {
  const playwright = spawnSync(process.execPath, [join(frontendDir, "node_modules", "@playwright", "test", "cli.js"), "test", ...process.argv.slice(2)], {
    cwd: frontendDir,
    env,
    stdio: "inherit",
    timeout: 180_000,
  });
  exitCode = playwright.status ?? 1;
  if (playwright.error) process.stderr.write(`${playwright.error.message}\n`);
}
if (prepare.error) process.stderr.write(`${prepare.error.message}\n`);

const resolvedTemp = resolve(tempDir);
if (dirname(resolvedTemp) !== tempParent || !resolvedTemp.split(/[\\/]/).at(-1)?.startsWith("sentinel-ai-e2e-")) {
  throw new Error("Refusing to remove a path outside the generated E2E temporary directory.");
}
rmSync(resolvedTemp, { recursive: true, force: true });
process.exitCode = exitCode;
