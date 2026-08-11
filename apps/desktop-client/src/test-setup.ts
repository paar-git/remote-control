/**
 * Vitest setup for the client.
 *
 * Tauri is not present under jsdom, so `@tauri-apps/api/core` is stubbed. Individual
 * tests override `invoke` to exercise specific backend responses.
 */

import '@testing-library/jest-dom/vitest';

import { vi } from 'vitest';

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));
