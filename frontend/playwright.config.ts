import { defineConfig, devices } from '@playwright/test'

const executablePath = process.env.IPSEC_SENTINEL_CHROMIUM_PATH
const bridgeCommand = process.env.IPSEC_SENTINEL_E2E_BRIDGE_COMMAND

export default defineConfig({
  testDir: './e2e',
  outputDir: './artifacts/playwright-results',
  fullyParallel: false,
  workers: 1,
  reporter: 'line',
  use: {
    baseURL: 'http://127.0.0.1:4173',
    trace: 'retain-on-failure',
    launchOptions: executablePath ? { executablePath } : undefined,
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: [
    ...(bridgeCommand ? [{ command: bridgeCommand, url: 'http://127.0.0.1:8787/api/health', reuseExistingServer: false, timeout: 120_000 }] : []),
    { command: 'npm run dev -- --host 127.0.0.1 --port 4173 --strictPort', url: 'http://127.0.0.1:4173', reuseExistingServer: false, timeout: 120_000 },
  ],
})
