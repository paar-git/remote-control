import { describe, expect, it } from 'vitest';

import {
  MODIFIER_BITS,
  buttonName,
  modifierBits,
  pointerFraction,
  type Fraction,
} from './inputCapture.js';

/** A rect with only the fields `pointerFraction` reads. */
function rect(left: number, top: number, width: number, height: number): DOMRect {
  return { left, top, width, height } as DOMRect;
}

describe('pointerFraction', () => {
  it('maps a click to a fraction of the surface, not to raw pixels', () => {
    // The host multiplies this by its own resolution, so sending pixels would put the
    // pointer somewhere else entirely on any machine with a different screen.
    expect(pointerFraction({ clientX: 500, clientY: 250 }, rect(100, 50, 800, 400))).toEqual({
      x: 0.5,
      y: 0.5,
    });
  });

  it('clamps a drag that leaves the surface', () => {
    // Releasing outside the canvas must not send a fraction above 1.0, which would
    // land the remote pointer off-screen.
    expect(pointerFraction({ clientX: 250, clientY: -40 }, rect(0, 0, 100, 100))).toEqual({
      x: 1,
      y: 0,
    });
  });

  it('reports the top-left corner rather than dividing by zero on an unlaid-out canvas', () => {
    // A canvas measured before layout has zero width; NaN would cross the IPC boundary
    // and move the remote pointer nowhere in particular.
    const fraction: Fraction = pointerFraction({ clientX: 10, clientY: 10 }, rect(0, 0, 0, 0));
    expect(fraction).toEqual({ x: 0, y: 0 });
  });
});

describe('modifierBits', () => {
  it('names modifiers by role so a Mac Command key is META, not a Windows key', () => {
    const event = { ctrlKey: false, altKey: false, shiftKey: false, metaKey: true };
    expect(modifierBits(event as KeyboardEvent)).toBe(0b0000_1000);
  });

  it('combines held modifiers into one mask', () => {
    const event = { ctrlKey: true, altKey: false, shiftKey: true, metaKey: false };
    expect(modifierBits(event as KeyboardEvent)).toBe(0b0000_0011);
  });

  it('sends nothing when no modifier is held', () => {
    const event = { ctrlKey: false, altKey: false, shiftKey: false, metaKey: false };
    expect(modifierBits(event as KeyboardEvent)).toBe(0);
  });

  it('matches the bit layout the Rust Modifiers type defines', () => {
    // These bits are re-declared here on the TypeScript side, so a change to
    // `crates/protocol/src/input.rs` that this file does not follow would silently
    // send the wrong modifier rather than failing to compile.
    expect(MODIFIER_BITS).toEqual({
      shift: 0b0000_0001,
      control: 0b0000_0010,
      alt: 0b0000_0100,
      meta: 0b0000_1000,
    });
  });
});

describe('buttonName', () => {
  it('names the buttons the protocol knows', () => {
    expect([0, 1, 2, 3, 4].map(buttonName)).toEqual(['left', 'middle', 'right', 'back', 'forward']);
  });

  it('drops a button the protocol has no name for rather than guessing', () => {
    // Sending an unknown button as "left" would click something on the remote machine
    // that the operator never asked to click.
    expect(buttonName(9)).toBeNull();
  });
});
