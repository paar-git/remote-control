/**
 * Decoding the region messages the Rust side pushes down the IPC channel.
 *
 * The wire format is deliberately minimal — x, y, width, height as little-endian
 * u32, then raw RGBA — because the pixels arrive already decompressed and in the
 * exact byte order `putImageData` wants. Nothing here re-encodes or converts.
 */

/** Bytes of header before the pixels. */
const HEADER_BYTES = 16;

/** Bytes per pixel, RGBA. */
const BYTES_PER_PIXEL = 4;

/** One rectangular screen update. */
export interface Region {
  readonly x: number;
  readonly y: number;
  readonly width: number;
  readonly height: number;
  readonly pixels: Uint8ClampedArray<ArrayBuffer>;
}

/**
 * Read one region message.
 *
 * @throws if the message is too short, or its pixel count disagrees with its
 * dimensions — a truncated message must never be blitted as though it were whole.
 */
export function parseRegion(buffer: ArrayBuffer): Region {
  if (buffer.byteLength < HEADER_BYTES) {
    throw new Error(`region message of ${buffer.byteLength} bytes is shorter than its header`);
  }
  const view = new DataView(buffer);
  const x = view.getUint32(0, true);
  const y = view.getUint32(4, true);
  const width = view.getUint32(8, true);
  const height = view.getUint32(12, true);

  const expected = width * height * BYTES_PER_PIXEL;
  const actual = buffer.byteLength - HEADER_BYTES;
  if (actual !== expected) {
    throw new Error(`region ${width}x${height} needs ${expected} bytes of pixels, got ${actual}`);
  }

  return { x, y, width, height, pixels: new Uint8ClampedArray(buffer, HEADER_BYTES) };
}

/** Blit one region message onto `ctx` at the position it names. */
export function applyRegion(ctx: CanvasRenderingContext2D, buffer: ArrayBuffer): void {
  const { x, y, width, height, pixels } = parseRegion(buffer);
  ctx.putImageData(new ImageData(pixels, width, height), x, y);
}
