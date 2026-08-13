/**
 * Vitest setup for the client.
 *
 * Tauri is not present under jsdom, so `@tauri-apps/api/core` and `.../event` are both
 * stubbed. Individual tests override `invoke` to exercise specific backend responses.
 *
 * `listen` resolves to a no-op unlisten function rather than being left undefined: a
 * component that subscribes to an event does so in a promise nothing awaits, so an
 * unmocked module surfaces as an unhandled rejection in an unrelated test rather than
 * as a failure in the one that caused it.
 */

import '@testing-library/jest-dom/vitest';

import { vi } from 'vitest';

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn(() => Promise.resolve(() => undefined)),
}));
