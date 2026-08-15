/**
 * Moving between remote displays as the pointer reaches their edges.
 *
 * # The decision, in one place
 *
 * Every pointer sample asks the same question: has this reached an edge, and is there a
 * display beyond it? The answer depends on the arrangement, the operator's saved
 * preference, and whether they have already been asked. Keeping all of that here means
 * the session view only has to report where the pointer is, and the rules stay
 * testable without rendering anything.
 *
 * # A crossing is not a suggestion
 *
 * When a switch happens — automatically, or because the operator said Move — the
 * pointer is placed at the *corresponding* point on the new display, not at the same
 * fraction. See `crossDisplay`. The operator's hand does not move, so neither should
 * the cursor.
 *
 * # Asking does not repeat
 *
 * Once a durable preference exists, no prompt is ever shown again. Until then, a
 * pending prompt suppresses further prompts, so dragging along an edge cannot stack up
 * a queue of dialogs.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import {
  DEFAULT_PREFERENCES,
  adjacentDisplay,
  crossDisplay,
  edgeAt,
  findDisplay,
  loadPreferences,
  primaryDisplay,
  resolveDisplay,
  savePreferences,
  type Crossing,
  type DisplayPreferences,
  type Edge,
  type RemoteDisplay,
  type SwitchMode,
} from './displays';

/** A crossing waiting on the operator's answer. */
export interface PendingSwitch {
  readonly edge: Edge;
  readonly along: number;
  readonly crossing: Crossing;
}

export interface DisplayNavigation {
  /** The display being viewed. */
  readonly active: number;
  /** The prompt to show, if one is waiting. */
  readonly pending: PendingSwitch | null;
  /** The saved preferences. */
  readonly preferences: DisplayPreferences;
  /**
   * Report a pointer position on the active display.
   *
   * Returns a crossing when the view should move there now, and `null` otherwise —
   * including when a prompt was raised, because nothing moves until it is answered.
   */
  readonly onPointer: (x: number, y: number) => Crossing | null;
  /** Answer a pending prompt. */
  readonly decide: (decision: { move: boolean; mode: SwitchMode | null }) => Crossing | null;
  /** Change display directly, from the picker. */
  readonly select: (index: number) => void;
  /** Change and persist the switching preference. */
  readonly setPreferences: (next: DisplayPreferences) => void;
}

export function useDisplayNavigation(
  displays: readonly RemoteDisplay[],
  storage?: Storage,
): DisplayNavigation {
  const [preferences, setPreferencesState] = useState<DisplayPreferences>(() =>
    storage === undefined ? loadPreferences() : loadPreferences(storage),
  );
  const [active, setActive] = useState<number>(() => primaryDisplay(displays)?.index ?? 0);
  const [pending, setPending] = useState<PendingSwitch | null>(null);

  // Read inside the pointer callback without making it a new function on every sample.
  const state = useRef({ active, preferences, pending, displays });
  state.current = { active, preferences, pending, displays };

  // The arrangement can change under a live session. If the display being viewed goes
  // away, follow it to the primary rather than aiming at a monitor that no longer
  // exists; any pending prompt is dropped, since it referred to the old arrangement.
  useEffect(() => {
    if (displays.length === 0) return;
    const resolved = resolveDisplay(displays, active);
    if (resolved !== null && resolved !== active) {
      setActive(resolved);
      setPending(null);
    }
  }, [displays, active]);

  // A pending prompt whose target vanished must not stay on screen.
  useEffect(() => {
    if (pending !== null && findDisplay(displays, pending.crossing.display) === null) {
      setPending(null);
    }
  }, [displays, pending]);

  const onPointer = useCallback((x: number, y: number): Crossing | null => {
    const current = state.current;

    // One prompt at a time: dragging along an edge must not queue dialogs.
    if (current.pending !== null) return null;
    if (current.preferences.switchMode === 'never') return null;

    const edge = edgeAt(x, y);
    if (edge === null) return null;

    const along = edge === 'left' || edge === 'right' ? y : x;
    if (adjacentDisplay(current.displays, current.active, edge) === null) return null;

    const crossing = crossDisplay(current.displays, current.active, edge, along);
    if (crossing === null) return null;

    if (current.preferences.switchMode === 'automatic') {
      setActive(crossing.display);
      return crossing;
    }

    setPending({ edge, along, crossing });
    return null;
  }, []);

  const decide = useCallback(
    (decision: { move: boolean; mode: SwitchMode | null }): Crossing | null => {
      const waiting = state.current.pending;
      setPending(null);

      if (decision.mode !== null) {
        const next = { ...state.current.preferences, switchMode: decision.mode };
        setPreferencesState(next);
        if (storage === undefined) savePreferences(next);
        else savePreferences(next, storage);
      }

      if (!decision.move || waiting === null) return null;
      setActive(waiting.crossing.display);
      return waiting.crossing;
    },
    [storage],
  );

  const select = useCallback((index: number): void => {
    setPending(null);
    setActive(index);
  }, []);

  const setPreferences = useCallback(
    (next: DisplayPreferences): void => {
      setPreferencesState(next);
      if (storage === undefined) savePreferences(next);
      else savePreferences(next, storage);
    },
    [storage],
  );

  return useMemo(
    () => ({ active, pending, preferences, onPointer, decide, select, setPreferences }),
    [active, pending, preferences, onPointer, decide, select, setPreferences],
  );
}

/** The starting preferences, exported so Settings can offer a reset. */
export { DEFAULT_PREFERENCES };
