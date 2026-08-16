/**
 * The remote display.
 *
 * # A blank canvas is a lie
 *
 * A canvas with nothing painted on it looks exactly like a canvas whose stream has
 * died. This component never shows one: it is either painting frames, or it is an
 * `alert` naming the reason it is not — at start, or at any point after, since
 * `video://stream-ended` fires on every way a stream can end (see `videoApi.ts`).
 *
 * # The canvas is sized to the stream, not to its container
 *
 * `width`/`height` are the canvas's pixel buffer, set from what the agent actually
 * negotiated. Leaving them at the HTML default (300x150) would silently scale every
 * frame `putImageData` draws, which looks like a blurry remote rather than a bug here.
 * `fitted` controls the *display* size on top of that — CSS, not the buffer.
 */

import { useEffect, useRef, useState } from 'react';

import { applyRegion } from './video.js';
import { listenStreamEnded, startStream, stopStream, type StreamStarted } from './videoApi.js';

/** Frames requested per second. The agent may negotiate something slower. */
const MAX_FPS = 30;

export function VideoSurface({
  displayIndex,
  fitted,
}: {
  /** Which of the agent's displays to capture. */
  readonly displayIndex: number;
  /** Scale to fit the pane (`object-fit: contain`) rather than showing 1:1 pixels. */
  readonly fitted: boolean;
}): React.JSX.Element {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [started, setStarted] = useState<StreamStarted | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setError(null);
    setStarted(null);

    const onFrame = (buffer: ArrayBuffer): void => {
      const ctx = canvasRef.current?.getContext('2d');
      if (ctx === null || ctx === undefined) return;
      try {
        applyRegion(ctx, buffer);
      } catch (err) {
        if (!cancelled) {
          setError(
            err instanceof Error
              ? err.message
              : 'The video stream sent a frame that could not be drawn.',
          );
        }
      }
    };

    startStream(displayIndex, MAX_FPS, onFrame)
      .then((result) => {
        if (!cancelled) setStarted(result);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Could not start the video stream.');
        }
      });

    return () => {
      cancelled = true;
      stopStream().catch(() => undefined);
    };
  }, [displayIndex]);

  // Independent of the effect above: a stream can end at any point in its life, not
  // only fail to start, and the surface showing it must say which happened.
  useEffect(() => {
    let cancelled = false;
    let unlisten: (() => void) | undefined;

    listenStreamEnded((ended) => {
      if (!cancelled) setError(ended.message);
    })
      .then((stop) => {
        if (cancelled) stop();
        else unlisten = stop;
      })
      .catch(() => undefined);

    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);

  if (error !== null) {
    return (
      <div
        role="alert"
        className="flex h-full w-full items-center justify-center p-6 text-center text-sm text-(--color-text-secondary)"
      >
        {error}
      </div>
    );
  }

  return (
    <div
      className={
        fitted
          ? 'flex h-full w-full items-center justify-center overflow-hidden'
          : 'h-full w-full overflow-auto'
      }
    >
      <canvas
        ref={canvasRef}
        data-testid="video-surface"
        width={started?.width ?? 0}
        height={started?.height ?? 0}
        className={fitted ? 'max-h-full max-w-full object-contain' : undefined}
      />
    </div>
  );
}
