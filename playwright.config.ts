import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: './e2e',
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
  use: {
    baseURL: 'http://localhost:4635/crypto-lab-entropy-collapse/',
    colorScheme: 'dark',
  },
  webServer: {
    // Build first: `vite preview` only serves the existing dist/, so without
    // this a broken build leaves the last good bundle in place and the suite
    // passes green against source that no longer compiles.
    command: 'npm run build && npm run preview -- --port 4635 --strictPort',
    url: 'http://localhost:4635/crypto-lab-entropy-collapse/',
    reuseExistingServer: !process.env.CI,
  },
})
