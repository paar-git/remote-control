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

/**
 * jsdom implements no Canvas API at all — not even the plain-data `ImageData`
 * constructor, which does not touch a canvas itself. The video pipeline's tests
 * construct one to hand to `putImageData`, so a minimal stand-in is provided here
 * rather than in each test file.
 *
 * This stand-in is looser than a real browser's: it does not throw when `data.length`
 * disagrees with `width * height * 4`, as a real `ImageData` constructor does. That gap
 * is harmless today only because `video.ts`'s `parseRegion` already enforces that exact
 * invariant before an `ImageData` is ever constructed — this polyfill must not be relied
 * on to catch it, because it will not.
 */
if (typeof globalThis.ImageData === 'undefined') {
  class ImageDataPolyfill {
    readonly data: Uint8ClampedArray;
    readonly width: number;
    readonly height: number;

    constructor(data: Uint8ClampedArray, width: number, height?: number) {
      this.data = data;
      this.width = width;
      this.height = height ?? data.length / (4 * width);
    }
  }

  // @ts-expect-error -- a minimal stand-in, not a full `ImageData` implementation.
  globalThis.ImageData = ImageDataPolyfill;
}
