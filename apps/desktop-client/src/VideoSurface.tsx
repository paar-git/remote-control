/**
 * The remote display, and the surface the operator drives it from.
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
 *
 * # Input is captured only while the surface holds focus
 *
 * Otherwise the operator could not use their own machine while a session is open: every
 * keystroke meant for another window would be forwarded to the remote one. Focus makes
 * the boundary something the operator controls and can see. While focused, keystrokes
 * are `preventDefault`ed so the browser does not also act on them locally — a `Ctrl+R`
 * meant for the remote machine must not reload this app.
 *
 * # Held keys are released when capture stops
 *
 * Blur, unmount and a dying stream all end capture mid-chord. Whatever the operator was
 * holding is released explicitly on the way out, because the host has no other way to
 * learn the key came up and would otherwise repeat it forever.
 */

import { useCallback, useEffect, useRef, useState } from 'react';

import type { Crossing } from './displays';
import { buttonName, modifierBits, pointerFraction } from './inputCapture.js';
import {
  listenInputAck,
  listenInputApplied,
  sendKey,
  sendPointerButton,
  sendPointerMove,
  sendScroll,
} from './inputApi.js';
import { applyRegion } from './video.js';
import { listenStreamEnded, startStream, stopStream, type StreamStarted } from './videoApi.js';

/** Frames requested per second. The agent may negotiate something slower. */
const MAX_FPS = 30;

/**
 * How many unapplied events mean the host is genuinely behind rather than merely busy.
 *
 * A live session always has a few in flight — pointer motion alone issues a sequence
 * number per sample — so a low threshold would warn constantly. This is roughly a
 * second of continuous pointer movement.
 */
const LAG_THRESHOLD = 60;

export function VideoSurface({
  displayIndex,
  fitted,
  capturing,
  passthrough,
  onPointerSample,
}: {
  /** Which of the agent's displays to capture. */
  readonly displayIndex: number;
  /** Scale to fit the pane (`object-fit: contain`) rather than showing 1:1 pixels. */
  readonly fitted: boolean;
  /**
   * Whether this surface forwards input at all.
   *
   * Required rather than optional: an optional prop here would let a caller ship a
   * surface that looks live and silently drops every keystroke.
   */
  readonly capturing: boolean;
  /**
   * Send chords literally instead of letting them be recognised as intents.
   *
   * Required rather than optional, matching {@link capturing}: a caller that forgot it
   * would ship a toggle that looks live and changes nothing, which is the exact defect
   * this escape hatch already had once.
   */
  readonly passthrough: boolean;
  /**
   * Report where the pointer landed, as a fraction of the display being viewed.
   *
   * Returns a crossing when that position means the view should move to another
   * monitor, and `null` otherwise. The decision lives in `useDisplayNavigation`, which
   * owns the arrangement and the operator's preference; this surface only knows where
   * the pointer is.
   */
  readonly onPointerSample: (x: number, y: number) => Crossing | null;
}): React.JSX.Element {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [started, setStarted] = useState<StreamStarted | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [focused, setFocused] = useState(false);
  const [refusal, setRefusal] = useState<string | null>(null);
  const [lagging, setLagging] = useState(false);

  // Codes currently held down, so they can be released if capture ends mid-chord.
  const heldKeys = useRef(new Set<string>());

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

  /** Release every key still held, so the host does not repeat one forever. */
  const releaseHeldKeys = useCallback(() => {
    for (const code of heldKeys.current) {
      void sendKey({ code, down: false, repeat: false, modifiers: 0, passthrough: false }).catch(
        () => undefined,
      );
    }
    heldKeys.current.clear();
  }, []);

  // Unmount is the one exit this component cannot see as an event: the operator closing
  // the session while holding a key would otherwise leave it held on the remote machine.
  useEffect(() => releaseHeldKeys, [releaseHeldKeys]);

  // Losing the ability to capture — the toggle going off, or the stream dying — must
  // release just as blur does, since no keyup will arrive for what is already held.
  useEffect(() => {
    if (!capturing || error !== null) releaseHeldKeys();
  }, [capturing, error, releaseHeldKeys]);

  const active = capturing && error === null;

  // A host that refuses input looks exactly like one that has frozen. It refuses for
  // reasons the operator can often act on — a revoked grant, a missing macOS
  // accessibility permission — so the reason is worth showing rather than dropping.
  useEffect(() => {
    if (!active) return undefined;

    let cancelled = false;
    let unlisten: (() => void) | undefined;

    listenInputAck((ack) => {
      if (cancelled) return;
      // Cleared by the next event the host does accept, so a permission granted
      // mid-session stops warning on its own rather than needing a reconnect.
      setRefusal(ack.ok ? null : (ack.reason ?? 'The other machine refused the input.'));
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
  }, [active]);

  // Falling behind is not the same failure as being refused, and not the same as a dead
  // link: the ping stays healthy while a busy host queues up everything sent to it.
  useEffect(() => {
    if (!active) return undefined;

    let cancelled = false;
    let unlisten: (() => void) | undefined;

    listenInputApplied((applied) => {
      if (!cancelled) setLagging(applied.outstanding > LAG_THRESHOLD);
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
  }, [active]);

  // `wheel` is attached natively rather than through React, which registers it passively
  // at the root: a passive listener cannot `preventDefault`, so the operator's own page
  // would scroll alongside the remote one.
  useEffect(() => {
    const canvas = canvasRef.current;
    if (canvas === null || !active) return undefined;

    const onWheel = (event: WheelEvent): void => {
      if (document.activeElement !== canvas) return;
      event.preventDefault();
      void sendScroll(event.deltaX, event.deltaY).catch(() => undefined);
    };

    canvas.addEventListener('wheel', onWheel, { passive: false });
    return () => {
      canvas.removeEventListener('wheel', onWheel);
    };
  }, [active]);

  const onPointerMove = (event: React.PointerEvent<HTMLCanvasElement>): void => {
    if (!active) return;
    const { x, y } = pointerFraction(event, event.currentTarget.getBoundingClientRect());

    // Reaching an edge with a monitor beyond it moves the pointer onto that monitor
    // instead, at the point that continues the same motion — so the operator's hand
    // does not have to stop at a seam.
    const crossing = onPointerSample(x, y);
    if (crossing !== null) {
      void sendPointerMove(crossing.x, crossing.y, crossing.display).catch(() => undefined);
      return;
    }

    void sendPointerMove(x, y, displayIndex).catch(() => undefined);
  };

  const onPointerButton = (event: React.PointerEvent<HTMLCanvasElement>, down: boolean): void => {
    if (!active) return;
    const name = buttonName(event.button);
    if (name === null) return;
    event.preventDefault();
    // Focus on press, so clicking the remote screen starts forwarding the keyboard too
    // rather than requiring a separate Tab to this surface.
    if (down) event.currentTarget.focus();
    void sendPointerButton(name, down).catch(() => undefined);
  };

  const onKey = (event: React.KeyboardEvent<HTMLCanvasElement>, down: boolean): void => {
    if (!active) return;
    // The operator aimed this at the remote machine; the local browser must not also
    // act on it.
    event.preventDefault();

    if (down) heldKeys.current.add(event.code);
    else heldKeys.current.delete(event.code);

    void sendKey({
      code: event.code,
      down,
      repeat: event.repeat,
      modifiers: modifierBits(event),
      passthrough,
    }).catch(() => undefined);
  };

  // Most urgent first: a refusal means nothing is getting through, falling behind means
  // it is but late, and passthrough is merely a mode the operator chose.
  const status: { message: string; urgent: boolean } | null =
    refusal !== null
      ? { message: `Input refused: ${refusal}`, urgent: true }
      : lagging
        ? { message: 'The remote machine is behind on input', urgent: true }
        : passthrough
          ? { message: 'Shortcuts are sent literally', urgent: false }
          : null;

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
        // Focusable only while capturing: a surface that takes focus but forwards
        // nothing is a keyboard trap for anyone tabbing through the session screen.
        tabIndex={capturing ? 0 : undefined}
        role={capturing ? 'application' : undefined}
        aria-label={capturing ? 'Remote screen. Click to send keyboard and mouse input.' : undefined}
        onFocus={() => {
          setFocused(true);
        }}
        onBlur={() => {
          setFocused(false);
          releaseHeldKeys();
        }}
        onPointerMove={onPointerMove}
        onPointerDown={(event) => {
          onPointerButton(event, true);
        }}
        onPointerUp={(event) => {
          onPointerButton(event, false);
        }}
        onKeyDown={(event) => {
          onKey(event, true);
        }}
        onKeyUp={(event) => {
          onKey(event, false);
        }}
        onContextMenu={(event) => {
          // Right-click belongs to the remote machine; the local menu would cover it.
          if (active) event.preventDefault();
        }}
        className={[
          fitted ? 'max-h-full max-w-full object-contain' : '',
          // Say plainly where input is going. Without this the only difference between
          // a focused and an unfocused surface is whether keystrokes vanish.
          active && focused ? 'outline-2 outline-(--color-accent)' : 'outline-none',
        ]
          .filter(Boolean)
          .join(' ')}
      />

      {/* One status line, most urgent wins. An operator whose input is being rejected
          does not also need to be told how it was encoded, and one whose host has
          stopped applying anything does not need to hear about the encoding either. */}
      {active && status !== null && (
        <p
          role="status"
          className={
            'pointer-events-none fixed bottom-4 left-1/2 z-40 -translate-x-1/2 rounded-lg ' +
            'border px-3 py-1.5 text-xs shadow-lg ' +
            (status.urgent
              ? 'border-(--color-danger) bg-(--color-card) text-(--color-text)'
              : 'border-(--color-border) bg-(--color-card) text-(--color-text-secondary)')
          }
        >
          {status.message}
        </p>
      )}
    </div>
  );
}
