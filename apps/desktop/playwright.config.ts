import { defineConfig } from "@playwright/test";

const browserChannel =
  process.env.VEYRA_E2E_BROWSER_CHANNEL ??
  (process.platform === "win32" ? "msedge" : undefined);

export default defineConfig({
  testDir: "./e2e",
  outputDir: "../../test-results/desktop",
  fullyParallel: false,
  retries: 0,
  reporter: "line",
  use: {
    baseURL: process.env.VEYRA_E2E_UI_URL ?? "http://127.0.0.1:1420",
    ...(browserChannel === undefined ? {} : { channel: browserChannel }),
    trace: "retain-on-failure",
  },
});
