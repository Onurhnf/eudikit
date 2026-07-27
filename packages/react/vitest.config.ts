import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts', 'test/**/*.test.tsx'],
    // The package is a browser transport; the server-rendering smoke test opts out per file.
    environment: 'jsdom',
  },
})
