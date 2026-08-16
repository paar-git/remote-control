import { describe, expect, it, vi } from 'vitest';
import { applyRegion, parseRegion } from './video';

function region(x: number, y: number, w: number, h: number, pixels: number[]): ArrayBuffer {
  const buffer = new ArrayBuffer(16 + pixels.length);
  const view = new DataView(buffer);
  view.setUint32(0, x, true);
  view.setUint32(4, y, true);
  view.setUint32(8, w, true);
  view.setUint32(12, h, true);
  new Uint8Array(buffer, 16).set(pixels);
  return buffer;
}

describe('parseRegion', () => {
  it('reads the little-endian header the Rust side writes', () => {
    const parsed = parseRegion(region(64, 128, 2, 1, [1, 2, 3, 4, 5, 6, 7, 8]));
    expect(parsed).toMatchObject({ x: 64, y: 128, width: 2, height: 1 });
    expect(Array.from(parsed.pixels)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
  });

  it('rejects a region whose pixels do not match its dimensions', () => {
    // A truncated message must not be blitted as though it were whole; that would
    // paint uninitialised memory onto the operator's screen.
    expect(() => parseRegion(region(0, 0, 4, 4, [1, 2, 3, 4]))).toThrow();
  });
});

describe('applyRegion', () => {
  it('blits at the region position, not the origin', () => {
    // Ignoring the offset puts every update in the top-left corner — the classic
    // symptom of dropping the header.
    const putImageData = vi.fn();
    const ctx = { putImageData } as unknown as CanvasRenderingContext2D;

    applyRegion(ctx, region(64, 128, 1, 1, [9, 8, 7, 6]));

    expect(putImageData).toHaveBeenCalledTimes(1);
    const [image, x, y] = putImageData.mock.calls[0] as [ImageData, number, number];
    expect([x, y]).toEqual([64, 128]);
    expect(image.width).toBe(1);
    expect(image.height).toBe(1);
  });
});
