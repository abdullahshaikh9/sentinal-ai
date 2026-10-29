import { defineConfig } from "@playwright/test";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const frontend = dirname(fileURLToPath(import.meta.url));
const root = resolve(frontend, "..");
const backend = resolve(root, "backend");
const python = resolve(root, ".venv311", "Scripts", "python.exe");
const chrome = process.env.CHROME_EXECUTABLE ?? "C:/Program Files/Google/Chrome/Application/chrome.exe";
const vite = resolve(frontend, "node_modules", "vite", "bin", "vite.js");

export default defineConfig({
  testDir: "./e2e",
  testMatch: "*.spec.ts",
  outputDir: process.env.SENTINEL_E2E_OUTPUT_DIR ?? "./test-results",
  fullyParallel: false,
  workers: 1,
  reporter: "list",
  timeout: 20_000,
  expect: { timeout: 7_000 },
  use: {
    baseURL: "http://127.0.0.1:15173",
    browserName: "chromium",
    headless: true,
    launchOptions: { executablePath: chrome },
    trace: "off",
  },
  webServer: [
    {
      command: `"${python}" -m uvicorn app.main:app --host 127.0.0.1 --port 18081 --no-proxy-headers`,
      cwd: backend,
      url: "http://127.0.0.1:18081/api/v1/health",
      reuseExistingServer: false,
      timeout: 30_000,
    },
    {
      command: `"${process.execPath}" "${vite}" --host 127.0.0.1 --port 15173 --strictPort`,
      cwd: frontend,
      url: "http://127.0.0.1:15173",
      reuseExistingServer: false,
      timeout: 30_000,
    },
  ],
});
