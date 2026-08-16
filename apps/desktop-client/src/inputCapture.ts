/**
 * Turning browser input events into what the wire protocol wants.
 *
 * # Fractions, never pixels
 *
 * The canvas is whatever size the operator's window happens to be; the remote screen is
 * whatever size it is. Sending pixel coordinates would land the pointer somewhere else
 * entirely on any machine whose screen differs from the pane showing it. So the
 * controller sends a fraction of the surface and the host multiplies by its own
 * resolution — the same reason `InputEvent::MouseMove` is documented as normalised.
 *
 * # Modifiers are named by role
 *
 * `metaKey` is Command on macOS, the Windows key on Windows and Super on Linux. The
 * protocol names it `META` for exactly that reason, so this module never has to ask
 * which machine it is running on.
 *
 * Everything here is deliberately pure: the decisions worth testing are the arithmetic
 * and the bit layout, and neither needs a DOM or an IPC boundary to exercise.
 */

/** A point in viewport coordinates — the part of a pointer event this module reads. */
export interface ClientPoint {
  /** Viewport X, as `MouseEvent.clientX`. */
  readonly clientX: number;
  /** Viewport Y, as `MouseEvent.clientY`. */
  readonly clientY: number;
}

/** A position on the remote screen, each axis in `0..=1`. */
export interface Fraction {
  /** Fraction across, from the left edge. */
  readonly x: number;
  /** Fraction down, from the top edge. */
  readonly y: number;
}

/** The subset of a browser event carrying modifier state. */
export interface ModifierState {
  /** Whether Control is held. */
  readonly ctrlKey: boolean;
  /** Whether Alt / Option is held. */
  readonly altKey: boolean;
  /** Whether Shift is held. */
  readonly shiftKey: boolean;
  /** Whether Command / Windows / Super is held. */
  readonly metaKey: boolean;
}

/**
 * The bit for each modifier, mirroring `Modifiers` in `crates/protocol/src/input.rs`.
 *
 * Exported so a test can assert the layout: nothing at compile time ties these numbers
 * to the Rust constants, and a mismatch would not fail to build — it would quietly send
 * Control where the operator pressed Shift.
 */
export const MODIFIER_BITS = {
  /** `Modifiers::SHIFT`. */
  shift: 0b0000_0001,
  /** `Modifiers::CONTROL`. */
  control: 0b0000_0010,
  /** `Modifiers::ALT`. */
  alt: 0b0000_0100,
  /** `Modifiers::META`. */
  meta: 0b0000_1000,
} as const;

/**
 * Where a pointer event falls on a surface, as a fraction of it.
 *
 * Clamped into `0..=1`: a drag that leaves the canvas still reports a point on the
 * remote screen rather than one beyond its edge.
 *
 * @param point - The pointer event, in viewport coordinates.
 * @param rect - The surface's bounding box, from `getBoundingClientRect()`.
 */
export function pointerFraction(point: ClientPoint, rect: DOMRect): Fraction {
  return {
    x: fraction(point.clientX - rect.left, rect.width),
    y: fraction(point.clientY - rect.top, rect.height),
  };
}

/**
 * One axis as a clamped fraction.
 *
 * A zero-sized surface reports 0 rather than `NaN`. A canvas measured before layout has
 * no width, and `NaN` would cross the IPC boundary to move the remote pointer nowhere
 * in particular.
 */
function fraction(offset: number, size: number): number {
  if (size <= 0) return 0;
  return Math.min(1, Math.max(0, offset / size));
}

/**
 * The modifier mask for a keyboard or pointer event, in the protocol's bit layout.
 *
 * @param event - Any event carrying the four standard modifier flags.
 */
export function modifierBits(event: ModifierState): number {
  return (
    (event.shiftKey ? MODIFIER_BITS.shift : 0) |
    (event.ctrlKey ? MODIFIER_BITS.control : 0) |
    (event.altKey ? MODIFIER_BITS.alt : 0) |
    (event.metaKey ? MODIFIER_BITS.meta : 0)
  );
}

/**
 * The protocol's name for a mouse button number, or `null` for one it has no name for.
 *
 * `MouseEvent.button` numbers the extra buttons 3 and 4 as back and forward, which is
 * what the protocol calls them. Anything else — a stylus barrel, a sixth button — is
 * dropped rather than guessed at, matching how an unrecognised key code is dropped
 * rather than delivered as some other key.
 */
export function buttonName(button: number): string | null {
  switch (button) {
    case 0:
      return 'left';
    case 1:
      return 'middle';
    case 2:
      return 'right';
    case 3:
      return 'back';
    case 4:
      return 'forward';
    default:
      return null;
  }
}
