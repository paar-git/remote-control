/**
 * The remote machine's monitors, as the viewer understands them.
 *
 * # This mirrors the host, it does not decide
 *
 * The arrangement is whatever the host reported. Nothing here guesses at geometry,
 * invents a display, or renumbers one — an index means the same monitor on both sides,
 * and a stale index is resolved against the current list rather than assumed valid.
 *
 * The one thing this side owns is *navigation*: which display the operator is looking
 * at, whether reaching an edge should move them, and whether to ask first. Those are
 * viewer preferences, not facts about the remote machine, so they live here.
 *
 * # Geometry matches the Rust topology deliberately
 *
 * `adjacentDisplay` and `crossDisplay` reproduce the rules in `crates/input/src/
 * display.rs`: neighbours must overlap on the perpendicular axis, the nearest one wins,
 * and a crossing preserves the *physical* point rather than the fraction. Keeping the
 * two in step is what stops the viewer highlighting one monitor while the pointer lands
 * on another.
 */

import { z } from 'zod';

/** One monitor on the remote machine. */
export const displaySchema = z.object({
  /** Stable index, assigned left to right then top to bottom by the host. */
  index: z.number().int().min(0).max(255),
  /** Untrusted: reported by the remote OS. Rendered as text. */
  name: z.string(),
  /** Native width in physical pixels. */
  width: z.number().int().positive(),
  /** Native height in physical pixels. */
  height: z.number().int().positive(),
  /** e.g. 2 for a 200% display. */
  scaleFactor: z.number().positive(),
  /** Horizontal offset in the remote virtual desktop. */
  originX: z.number().int(),
  /** Vertical offset in the remote virtual desktop. */
  originY: z.number().int(),
  /** Whether the remote OS calls this its main display. */
  primary: z.boolean(),
  /** Refresh rate, when the platform reported one. */
  refreshHz: z.number().int().positive().nullable(),
});

export type RemoteDisplay = z.infer<typeof displaySchema>;

/** Which way the pointer left a display. */
export type Edge = 'left' | 'right' | 'top' | 'bottom';

/** Every edge, in a fixed order. */
export const EDGES: readonly Edge[] = ['left', 'right', 'top', 'bottom'] as const;

/** How near an edge the pointer must come, as a fraction of the display. */
export const EDGE_TOLERANCE = 0.004;

/**
 * How far inside the neighbour a crossing lands, in remote pixels.
 *
 * Matches `ENTRY_INSET` in the Rust topology, and exists for the same reason: a landing
 * point exactly on the seam can round back onto the display just left, and would sit
 * one sample away from bouncing.
 */
export const ENTRY_INSET = 2;

/** What should happen when the pointer reaches an edge with a display beyond it. */
export const switchModeSchema = z.enum(['ask', 'automatic', 'never']);

/** How edge crossings behave. */
export type SwitchMode = z.infer<typeof switchModeSchema>;

/** The viewer's multi-display preferences. */
export const displayPreferencesSchema = z.object({
  /** Ask, switch silently, or never switch from the edge. */
  switchMode: switchModeSchema,
  /** Show every display at once rather than one at a time. */
  allDisplays: z.boolean(),
});

export type DisplayPreferences = z.infer<typeof displayPreferencesSchema>;

/** Ask before switching: the safe default, since switching moves what you are seeing. */
export const DEFAULT_PREFERENCES: DisplayPreferences = {
  switchMode: 'ask',
  allDisplays: false,
};

/** Where preferences persist. Per machine, not per session. */
const STORAGE_KEY = 'rc.displayPreferences';

/**
 * Read saved preferences, falling back to the defaults.
 *
 * A corrupt or partial value is discarded rather than repaired: the defaults are
 * harmless, and a half-understood preference would make the viewer behave in a way the
 * operator never chose.
 */
export function loadPreferences(storage: Storage = localStorage): DisplayPreferences {
  try {
    const raw = storage.getItem(STORAGE_KEY);
    if (raw === null) return DEFAULT_PREFERENCES;
    const parsed = displayPreferencesSchema.safeParse(JSON.parse(raw));
    return parsed.success ? parsed.data : DEFAULT_PREFERENCES;
  } catch {
    return DEFAULT_PREFERENCES;
  }
}

/** Persist preferences. Failure is silent: a session must not break over storage. */
export function savePreferences(
  preferences: DisplayPreferences,
  storage: Storage = localStorage,
): void {
  try {
    storage.setItem(STORAGE_KEY, JSON.stringify(preferences));
  } catch {
    // Private browsing, a full quota, a locked profile. None of these are worth
    // interrupting a live session for, and the in-memory preference still applies.
  }
}

/** Forget the saved choice, returning to asking. Used by the Settings reset. */
export function resetPreferences(storage: Storage = localStorage): DisplayPreferences {
  try {
    storage.removeItem(STORAGE_KEY);
  } catch {
    // As above.
  }
  return DEFAULT_PREFERENCES;
}

/** The display with `index`, if it still exists. */
export function findDisplay(
  displays: readonly RemoteDisplay[],
  index: number,
): RemoteDisplay | null {
  return displays.find((display) => display.index === index) ?? null;
}

/** The primary display, or the first one when the host flags none. */
export function primaryDisplay(displays: readonly RemoteDisplay[]): RemoteDisplay | null {
  return displays.find((display) => display.primary) ?? displays[0] ?? null;
}

/**
 * The display a viewer on `index` should be showing.
 *
 * Returns `index` untouched while that monitor exists, and the primary when it does
 * not — so a monitor unplugged mid-session moves the viewer somewhere real instead of
 * leaving it pointed at nothing.
 */
export function resolveDisplay(displays: readonly RemoteDisplay[], index: number): number | null {
  if (findDisplay(displays, index) !== null) return index;
  return primaryDisplay(displays)?.index ?? null;
}

/** `[left, top, right, bottom]` in the remote virtual desktop. Right and bottom exclusive. */
export function bounds(display: RemoteDisplay): [number, number, number, number] {
  return [
    display.originX,
    display.originY,
    display.originX + display.width,
    display.originY + display.height,
  ];
}

/** How much two spans overlap, or zero. */
function overlap(aStart: number, aEnd: number, bStart: number, bEnd: number): number {
  return Math.max(0, Math.min(aEnd, bEnd) - Math.max(aStart, bStart));
}

/**
 * The display beyond `edge` of `index`, if one is there.
 *
 * A neighbour must overlap on the perpendicular axis, so two monitors that merely touch
 * at a corner are not adjacent — stepping between them would move the pointer somewhere
 * the operator was not aiming. Among real neighbours the nearest wins.
 */
export function adjacentDisplay(
  displays: readonly RemoteDisplay[],
  index: number,
  edge: Edge,
  at: number | null = null,
): number | null {
  const from = findDisplay(displays, index);
  if (from === null) return null;
  const [left, top, right, bottom] = bounds(from);

  let best: { miss: number; gap: number; index: number } | null = null;

  for (const candidate of displays) {
    if (candidate.index === index) continue;
    const [cLeft, cTop, cRight, cBottom] = bounds(candidate);

    let gap: number;
    let shared: number;
    switch (edge) {
      case 'left':
        gap = left - cRight;
        shared = overlap(top, bottom, cTop, cBottom);
        break;
      case 'right':
        gap = cLeft - right;
        shared = overlap(top, bottom, cTop, cBottom);
        break;
      case 'top':
        gap = top - cBottom;
        shared = overlap(left, right, cLeft, cRight);
        break;
      case 'bottom':
        gap = cTop - bottom;
        shared = overlap(left, right, cLeft, cRight);
        break;
    }

    if (gap < 0 || shared <= 0) continue;

    // How far the departure point is from this candidate. Zero when the pointer is
    // aimed straight at it, which is what makes a display spanning several others
    // pick the right one rather than always the lowest-numbered.
    let miss = 0;
    if (at !== null) {
      const [start, end] = edge === 'left' || edge === 'right' ? [cTop, cBottom] : [cLeft, cRight];
      if (at < start) miss = start - at;
      else if (at >= end) miss = at - end + 1;
    }

    const better =
      best === null ||
      miss < best.miss ||
      (miss === best.miss &&
        (gap < best.gap || (gap === best.gap && candidate.index < best.index)));
    if (better) best = { miss, gap, index: candidate.index };
  }

  return best?.index ?? null;
}

/** Which edge a normalised position is touching, or `null` away from the edges. */
export function edgeAt(x: number, y: number, tolerance = EDGE_TOLERANCE): Edge | null {
  // Horizontal first, so a corner resolves deterministically rather than on noise.
  if (x <= tolerance) return 'left';
  if (x >= 1 - tolerance) return 'right';
  if (y <= tolerance) return 'top';
  if (y >= 1 - tolerance) return 'bottom';
  return null;
}

/** Where the pointer lands after crossing. */
export interface Crossing {
  readonly display: number;
  readonly x: number;
  readonly y: number;
}

/** A normalised fraction as an offset into `extent`, never past the last pixel. */
function scale(fraction: number, extent: number): number {
  const clamped = Math.min(1, Math.max(0, fraction));
  return Math.min(Math.round(clamped * extent), Math.max(0, extent - 1));
}

/** An offset into `extent` as a normalised fraction, clamped. */
function fraction(offset: number, extent: number): number {
  if (extent <= 1) return 0;
  return Math.min(1, Math.max(0, offset / (extent - 1)));
}

/**
 * Step off `edge` of `index` at `along`, landing on the neighbour.
 *
 * The physical point is preserved rather than the fraction, so leaving a 1080p display
 * two-thirds down arrives at that same height on a 1440p neighbour whatever its offset.
 * Without this the cursor visibly jumps at every boundary between unlike monitors.
 */
export function crossDisplay(
  displays: readonly RemoteDisplay[],
  index: number,
  edge: Edge,
  along: number,
): Crossing | null {
  const from = findDisplay(displays, index);
  if (from === null) return null;
  const [left, top, right, bottom] = bounds(from);

  // The departure point, in shared remote coordinates.
  let gx: number;
  let gy: number;
  switch (edge) {
    case 'left':
      [gx, gy] = [left, top + scale(along, from.height)];
      break;
    case 'right':
      [gx, gy] = [right - 1, top + scale(along, from.height)];
      break;
    case 'top':
      [gx, gy] = [left + scale(along, from.width), top];
      break;
    case 'bottom':
      [gx, gy] = [left + scale(along, from.width), bottom - 1];
      break;
  }

  // Which neighbour depends on where the pointer left, not only which is nearest.
  const departure = edge === 'left' || edge === 'right' ? gy : gx;
  const neighbourIndex = adjacentDisplay(displays, index, edge, departure);
  if (neighbourIndex === null) return null;
  const into = findDisplay(displays, neighbourIndex);
  if (into === null) return null;
  const [nLeft, nTop, nRight, nBottom] = bounds(into);

  const insetX = Math.min(ENTRY_INSET, Math.floor((nRight - nLeft) / 2));
  const insetY = Math.min(ENTRY_INSET, Math.floor((nBottom - nTop) / 2));
  const clamp = (value: number, lo: number, hi: number): number =>
    Math.min(hi, Math.max(lo, value));

  let ex: number;
  let ey: number;
  switch (edge) {
    case 'left':
      [ex, ey] = [nRight - 1 - insetX, clamp(gy, nTop, nBottom - 1)];
      break;
    case 'right':
      [ex, ey] = [nLeft + insetX, clamp(gy, nTop, nBottom - 1)];
      break;
    case 'top':
      [ex, ey] = [clamp(gx, nLeft, nRight - 1), nBottom - 1 - insetY];
      break;
    case 'bottom':
      [ex, ey] = [clamp(gx, nLeft, nRight - 1), nTop + insetY];
      break;
  }

  return {
    display: neighbourIndex,
    x: fraction(ex - nLeft, into.width),
    y: fraction(ey - nTop, into.height),
  };
}

/** The rectangle enclosing every display, or `null` when there are none. */
export function virtualBounds(
  displays: readonly RemoteDisplay[],
): [number, number, number, number] | null {
  if (displays.length === 0) return null;
  let [left, top, right, bottom] = bounds(displays[0]!);
  for (const display of displays.slice(1)) {
    const [l, t, r, b] = bounds(display);
    left = Math.min(left, l);
    top = Math.min(top, t);
    right = Math.max(right, r);
    bottom = Math.max(bottom, b);
  }
  return [left, top, right, bottom];
}

/** A display's place in a miniature of the real arrangement, as CSS percentages. */
export interface LayoutBox {
  readonly display: RemoteDisplay;
  readonly left: number;
  readonly top: number;
  readonly width: number;
  readonly height: number;
}

/**
 * Lay the displays out proportionally, preserving the remote arrangement.
 *
 * Percentages of the enclosing rectangle rather than fixed sizes, so a monitor above
 * and left of the primary renders above and left — the picker shows the operator's real
 * desk, not a row of equal boxes that would be a different arrangement.
 */
export function layoutDisplays(displays: readonly RemoteDisplay[]): LayoutBox[] {
  const extent = virtualBounds(displays);
  if (extent === null) return [];
  const [left, top, right, bottom] = extent;
  const spanX = Math.max(1, right - left);
  const spanY = Math.max(1, bottom - top);

  return displays.map((display) => ({
    display,
    left: ((display.originX - left) / spanX) * 100,
    top: ((display.originY - top) / spanY) * 100,
    width: (display.width / spanX) * 100,
    height: (display.height / spanY) * 100,
  }));
}

/** A short description for a picker entry: `1920×1080 · 60 Hz · 200%`. */
export function describeDisplay(display: RemoteDisplay): string {
  const parts = [`${display.width}×${display.height}`];
  if (display.refreshHz !== null) parts.push(`${display.refreshHz} Hz`);
  if (display.scaleFactor !== 1) parts.push(`${Math.round(display.scaleFactor * 100)}%`);
  return parts.join(' · ');
}
