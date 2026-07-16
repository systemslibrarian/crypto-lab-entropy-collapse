import { defineConfig } from 'vitest/config'

// GitHub Pages project subpath. Read the real repo name; do not guess.
export default defineConfig({
  base: '/crypto-lab-entropy-collapse/',
  test: {
    // Only collect unit tests; keep Playwright specs in e2e/ out of Vitest.
    include: ['src/**/*.test.ts'],
  },
})
