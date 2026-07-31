import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
// `vitest/config` re-exports Vite's `defineConfig` with the `test` block typed.
import { defineConfig } from 'vitest/config';

/**
 * Vite configuration for the Tauri frontend.
 *
 * The dev server is deliberately bound to `127.0.0.1` and not to `0.0.0.0`: the
 * frontend must never be reachable from the network during development.
 */
export default defineConfig({
  plugins: [react(), tailwindcss()],

  // Tauri serves the built assets from the filesystem, so paths must be relative.
  base: './',

  server: {
    host: '127.0.0.1',
    port: 1420,
    strictPort: true,
  },

  build: {
    // Matches the Chromium/WebKit versions bundled with Tauri 2.
    target: 'es2022',
    sourcemap: true,
    outDir: 'dist',
    emptyOutDir: true,
  },

  test: {
    globals: true,
    environment: 'jsdom',
    include: ['src/**/*.test.{ts,tsx}'],
    setupFiles: ['./src/test-setup.ts'],
  },
});
