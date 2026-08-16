/**
 * Tauri command wrappers for the input channel — the controlling half of a session.
 *
 * Kept out of `api.ts` for the same reason `videoApi.ts` is: that file carries the repo
 * owner's own uncommitted, in-flight work.
 *
 * # Fire-and-forget on purpose
 *
 * Pointer motion is sampled continuously, and awaiting a round trip per sample would
 * make the pointer lag the operator's hand. These calls return promises so a caller
 * *may* wait, but the capture layer does not — it reports failures through
 * `input://ack` instead, which is where a refusal the operator needs to see (a revoked
 * `control_input` grant, most notably) actually arrives.
 */

import { z } from 'zod';

import { displaySchema, type RemoteDisplay } from './displays';
import { call } from './ipc.js';

/** What `sendKey` actually sent, so the interface can say when a chord was translated. */
export const keySentSchema = z.object({
  /**
   * The intent name (e.g. `"copy"`) when the chord was recognised and passthrough was
   * off; `null` when the physical key went instead, or the key is not carried.
   */
  asIntent: z.string().nullable(),
});

export type KeySent = z.infer<typeof keySentSchema>;

/** One acknowledgement from the host, carried on `input://ack`. */
export const inputAckSchema = z.object({
  seq: z.number().int().nonnegative(),
  ok: z.boolean(),
  reason: z.string().nullable(),
});

export type InputAck = z.infer<typeof inputAckSchema>;

/** Move the remote pointer to a fraction of `display`. */
export function sendPointerMove(x: number, y: number, display: number): Promise<null> {
  return call('input_pointer_move', z.null(), { x, y, display });
}

/** Press or release a remote mouse button, named as the protocol names it. */
export function sendPointerButton(button: string, down: boolean): Promise<null> {
  return call('input_pointer_button', z.null(), { button, down });
}

/** Scroll the remote screen by a wheel delta. */
export function sendScroll(deltaX: number, deltaY: number): Promise<null> {
  return call('input_scroll', z.null(), { deltaX, deltaY });
}

/**
 * Press or release a key, identified by its W3C `KeyboardEvent.code`.
 *
 * With `passthrough` set the chord always travels as its physical key, even when it is
 * a recognised intent — `Ctrl+C` in a remote terminal is SIGINT, not Copy.
 */
export function sendKey(args: {
  readonly code: string;
  readonly down: boolean;
  readonly repeat: boolean;
  readonly modifiers: number;
  readonly passthrough: boolean;
}): Promise<KeySent> {
  return call('input_key', keySentSchema, { ...args });
}

/**
 * Subscribe to host acknowledgements.
 *
 * Worth listening for: the host can refuse an event the operator sent — most often
 * because the `control_input` grant was revoked mid-session — and this client does not
 * enforce that permission itself, so a refusal read and dropped would leave the
 * operator typing into a screen that silently ignores them.
 */
export async function listenInputAck(handler: (ack: InputAck) => void): Promise<() => void> {
  const { listen } = await import('@tauri-apps/api/event');

  return listen('input://ack', (event) => {
    const parsed = inputAckSchema.safeParse(event.payload);
    if (parsed.success) handler(parsed.data);
  });
}

/**
 * Subscribe to the host's display arrangement.
 *
 * Pushed unprompted whenever it changes, not only on request. A monitor plugged in,
 * unplugged, rearranged or rescaled while a session is live changes where every
 * subsequent coordinate lands, and a viewer that had to poll would aim at a stale
 * layout in between.
 */
export async function listenDisplays(
  handler: (displays: RemoteDisplay[]) => void,
): Promise<() => void> {
  const { listen } = await import('@tauri-apps/api/event');

  return listen('input://displays', (event) => {
    const parsed = z.array(displaySchema).safeParse(event.payload);
    if (parsed.success) handler(parsed.data);
  });
}

/** How far the host has got through the input sent to it. */
export const inputAppliedSchema = z.object({
  watermark: z.number().int().nonnegative(),
  outstanding: z.number().int().nonnegative(),
});

export type InputApplied = z.infer<typeof inputAppliedSchema>;

/**
 * Subscribe to the host's applied watermark.
 *
 * A round-trip ping says the *link* is healthy, which is a different question from
 * whether the remote machine is keeping up with the typing. A host busy enough to fall
 * behind looks, from the operator's side, exactly like one that has stopped.
 */
export async function listenInputApplied(
  handler: (applied: InputApplied) => void,
): Promise<() => void> {
  const { listen } = await import('@tauri-apps/api/event');

  return listen('input://applied', (event) => {
    const parsed = inputAppliedSchema.safeParse(event.payload);
    if (parsed.success) handler(parsed.data);
  });
}

/**
 * Take the operator's own desktop shortcuts, or hand them back.
 *
 * `Alt+Tab` is the one that matters: the operator's window manager acts on it before
 * this app sees it, so without a grab it switches their local windows and the remote
 * machine never hears about it.
 *
 * Returns whether a grab is actually held. A platform with no backend refuses rather
 * than quietly taking nothing — an operator told the grab is on, whose Alt+Tab still
 * switches their local windows, would reasonably conclude the session was broken.
 */
export function setKeyGrab(surfaceFocused: boolean, forwardingInput: boolean): Promise<boolean> {
  return call('input_set_grab', z.boolean(), { surfaceFocused, forwardingInput });
}
