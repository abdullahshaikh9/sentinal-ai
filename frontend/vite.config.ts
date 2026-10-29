import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import type { ViteUserConfig } from "vitest/config";

const apiProxy = {
  "/api/v1": { target: "http://127.0.0.1:8001", changeOrigin: true },
};

export default defineConfig({
  // Vitest 2 resolves its Vite 5 peer separately from the app's Vite 6.
  plugins: react() as unknown as ViteUserConfig["plugins"],
  server: {
    proxy: apiProxy,
  },
  preview: { proxy: apiProxy },
  test: {
    environment: "jsdom",
    setupFiles: "./src/test/setup.ts",
    globals: true,
    exclude: ["e2e/**", "**/node_modules/**", "**/dist/**", "**/.{git,idea,cache,output,temp}/**"],
  }
});

