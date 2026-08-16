import { describe, expect, it } from 'vitest';

import {
  DEFAULT_PREFERENCES,
  EDGES,
  adjacentDisplay,
  crossDisplay,
  describeDisplay,
  edgeAt,
  layoutDisplays,
  loadPreferences,
  primaryDisplay,
  resetPreferences,
  resolveDisplay,
  savePreferences,
  virtualBounds,
  type RemoteDisplay,
} from './displays';

function display(
  index: number,
  originX: number,
  originY: number,
  width: number,
  height: number,
  primary = false,
  extra: Partial<RemoteDisplay> = {},
): RemoteDisplay {
  return {
    index,
    name: `Display ${index + 1}`,
    width,
    height,
    scaleFactor: 1,
    originX,
    originY,
    primary,
    refreshHz: 60,
    ...extra,
  };
}

/** Two 1080p monitors side by side. */
const sideBySide = [display(0, 0, 0, 1920, 1080, true), display(1, 1920, 0, 1920, 1080)];

/** Two across, one centred above — the arrangement from the brief. */
const tee = [
  display(0, 0, 0, 1920, 1080, true),
  display(1, 1920, 0, 1920, 1080),
  display(2, 960, -1080, 1920, 1080),
];

/** Mixed resolution and a vertical offset, where naive maths breaks. */
const mixed = [display(0, 0, 0, 1920, 1080, true), display(1, 1920, 200, 2560, 1440)];

/** This machine's real arrangement: a secondary at a negative origin. */
const negativeOrigin = [display(0, -1920, 0, 1920, 1080), display(1, 0, 0, 1920, 1080, true)];

describe('finding displays', () => {
  it('finds the primary', () => {
    expect(primaryDisplay(sideBySide)?.index).toBe(0);
    expect(primaryDisplay(negativeOrigin)?.index).toBe(1);
  });

  it('falls back to the first when none is flagged primary', () => {
    expect(primaryDisplay([display(3, 0, 0, 800, 600)])?.index).toBe(3);
  });

  it('has no primary when there are no displays', () => {
    expect(primaryDisplay([])).toBeNull();
    expect(virtualBounds([])).toBeNull();
    expect(resolveDisplay([], 0)).toBeNull();
  });

  it('keeps a display that still exists', () => {
    expect(resolveDisplay(sideBySide, 1)).toBe(1);
  });

  it('falls back to the primary when a display is unplugged', () => {
    // The monitor being viewed disappears mid-session.
    expect(resolveDisplay([sideBySide[0]!], 1)).toBe(0);
  });
});

describe('adjacency', () => {
  it('finds neighbours in all four directions', () => {
    expect(adjacentDisplay(tee, 0, 'right')).toBe(1);
    expect(adjacentDisplay(tee, 1, 'left')).toBe(0);
    expect(adjacentDisplay(tee, 0, 'top')).toBe(2);
    expect(adjacentDisplay(tee, 2, 'bottom')).toBe(0);
  });

  it('finds nothing off the outside edges', () => {
    expect(adjacentDisplay(sideBySide, 0, 'left')).toBeNull();
    expect(adjacentDisplay(sideBySide, 1, 'right')).toBeNull();
    expect(adjacentDisplay(sideBySide, 0, 'top')).toBeNull();
  });

  it('does not treat diagonal displays as adjacent', () => {
    // No shared edge: stepping across would land somewhere unintended.
    const diagonal = [display(0, 0, 0, 1920, 1080, true), display(1, 1920, 1080, 1920, 1080)];
    expect(adjacentDisplay(diagonal, 0, 'right')).toBeNull();
    expect(adjacentDisplay(diagonal, 0, 'bottom')).toBeNull();
  });

  it('picks the nearest in a row of three', () => {
    const row = [
      display(0, 0, 0, 1920, 1080, true),
      display(1, 1920, 0, 1920, 1080),
      display(2, 3840, 0, 1920, 1080),
    ];
    expect(adjacentDisplay(row, 0, 'right')).toBe(1);
    expect(adjacentDisplay(row, 2, 'left')).toBe(1);
  });

  it('handles a display at a negative origin', () => {
    expect(adjacentDisplay(negativeOrigin, 1, 'left')).toBe(0);
    expect(adjacentDisplay(negativeOrigin, 0, 'right')).toBe(1);
  });

  it('is symmetric in linear arrangements', () => {
    // Not asserted for the T shape: a display spanning two others has two equally
    // valid neighbours below it, so which one is correct depends on where the
    // pointer crosses. That case is covered by the crossing tests instead.
    for (const displays of [sideBySide, mixed, negativeOrigin]) {
      for (const from of displays) {
        for (const edge of EDGES) {
          const neighbour = adjacentDisplay(displays, from.index, edge);
          if (neighbour === null) continue;
          const opposite = { left: 'right', right: 'left', top: 'bottom', bottom: 'top' } as const;
          expect(adjacentDisplay(displays, neighbour, opposite[edge])).toBe(from.index);
        }
      }
    }
  });
});

describe('edge detection', () => {
  it('detects each edge within tolerance', () => {
    expect(edgeAt(0.001, 0.5)).toBe('left');
    expect(edgeAt(0.999, 0.5)).toBe('right');
    expect(edgeAt(0.5, 0.001)).toBe('top');
    expect(edgeAt(0.5, 0.999)).toBe('bottom');
  });

  it('detects nothing in the middle', () => {
    expect(edgeAt(0.5, 0.5)).toBeNull();
    expect(edgeAt(0.2, 0.8)).toBeNull();
  });

  it('resolves a corner deterministically', () => {
    expect(edgeAt(0, 0)).toBe('left');
  });
});

describe('crossing between displays', () => {
  it('lands on the neighbour at the same height', () => {
    const crossing = crossDisplay(sideBySide, 0, 'right', 0.6);
    expect(crossing?.display).toBe(1);
    expect(crossing!.y).toBeCloseTo(0.6, 2);
  });

  it('preserves the physical height across different resolutions', () => {
    // Display 0 is 1080 tall at y=0; display 1 is 1440 tall starting at y=200.
    // Leaving 0 at 60% is remote y=648, which on display 1 is ~0.311 — not 0.6.
    const crossing = crossDisplay(mixed, 0, 'right', 0.6);
    expect(crossing?.display).toBe(1);
    expect(crossing!.y).toBeCloseTo((648 - 200) / 1439, 2);
    // Emphatically not the naive answer.
    expect(Math.abs(crossing!.y - 0.6)).toBeGreaterThan(0.05);
  });

  it('clamps onto a neighbour that does not fully overlap', () => {
    // Leaving the top of display 0 aims above display 1, which starts 200px lower.
    const crossing = crossDisplay(mixed, 0, 'right', 0);
    expect(crossing?.display).toBe(1);
    expect(crossing!.y).toBeGreaterThanOrEqual(0);
    expect(crossing!.y).toBeLessThan(0.01);
  });

  it('lands clear of the boundary rather than on it', () => {
    // Matches the Rust inset: a landing point on the seam can round back across it.
    const crossing = crossDisplay(sideBySide, 0, 'right', 0.5)!;
    expect(crossing.x).toBeGreaterThan(0);
  });

  it('is reversible', () => {
    const out = crossDisplay(sideBySide, 0, 'right', 0.42)!;
    const back = crossDisplay(sideBySide, out.display, 'left', out.y)!;
    expect(back.display).toBe(0);
    expect(back.y).toBeCloseTo(0.42, 2);
  });

  it('works vertically', () => {
    const crossing = crossDisplay(tee, 0, 'top', 0.5);
    expect(crossing?.display).toBe(2);
    expect(crossing!.y).toBeGreaterThan(0.99);
  });

  it('does nothing with no neighbour', () => {
    expect(crossDisplay(sideBySide, 0, 'left', 0.5)).toBeNull();
  });

  it('always lands inside the target display', () => {
    for (const displays of [sideBySide, tee, mixed, negativeOrigin]) {
      for (const from of displays) {
        for (const edge of EDGES) {
          for (const along of [0, 0.25, 0.5, 0.75, 1]) {
            const crossing = crossDisplay(displays, from.index, edge, along);
            if (crossing === null) continue;
            expect(crossing.x).toBeGreaterThanOrEqual(0);
            expect(crossing.x).toBeLessThanOrEqual(1);
            expect(crossing.y).toBeGreaterThanOrEqual(0);
            expect(crossing.y).toBeLessThanOrEqual(1);
          }
        }
      }
    }
  });

  it('picks the display below the pointer when one spans two others', () => {
    // Display 2 sits above both 0 and 1. Leaving its left half must reach 0 and its
    // right half must reach 1; always taking the nearest would send half of these
    // crossings to the wrong monitor.
    expect(crossDisplay(tee, 2, 'bottom', 0.2)?.display).toBe(0);
    expect(crossDisplay(tee, 2, 'bottom', 0.9)?.display).toBe(1);
  });

  it('round trips through a spanning display', () => {
    for (const along of [0.1, 0.3, 0.7, 0.95]) {
      const down = crossDisplay(tee, 2, 'bottom', along)!;
      expect(crossDisplay(tee, down.display, 'top', down.x)?.display).toBe(2);
    }
  });

  it('does not overshoot a very small display', () => {
    const tiny = [display(0, 0, 0, 1920, 1080, true), display(1, 1920, 0, 2, 2)];
    const crossing = crossDisplay(tiny, 0, 'right', 0.5);
    expect(crossing?.display).toBe(1);
    expect(crossing!.x).toBeGreaterThanOrEqual(0);
    expect(crossing!.x).toBeLessThanOrEqual(1);
  });
});

describe('layout for the picker', () => {
  it('preserves the real arrangement proportionally', () => {
    const boxes = layoutDisplays(sideBySide);
    expect(boxes).toHaveLength(2);
    expect(boxes[0]!.left).toBeCloseTo(0);
    expect(boxes[1]!.left).toBeCloseTo(50);
    expect(boxes[0]!.width).toBeCloseTo(50);
  });

  it('places a display above the others above them', () => {
    // Not a row of equal boxes: the arrangement is the information.
    const boxes = layoutDisplays(tee);
    const above = boxes.find((box) => box.display.index === 2)!;
    const below = boxes.find((box) => box.display.index === 0)!;
    expect(above.top).toBeLessThan(below.top);
    expect(above.left).toBeGreaterThan(0);
  });

  it('handles negative origins', () => {
    const boxes = layoutDisplays(negativeOrigin);
    expect(boxes.every((box) => box.left >= 0)).toBe(true);
    expect(boxes.find((box) => box.display.index === 0)!.left).toBeCloseTo(0);
  });

  it('scales mixed resolutions by their real size', () => {
    const boxes = layoutDisplays(mixed);
    const small = boxes.find((box) => box.display.index === 0)!;
    const large = boxes.find((box) => box.display.index === 1)!;
    expect(large.width).toBeGreaterThan(small.width);
    expect(large.height).toBeGreaterThan(small.height);
  });

  it('lays out nothing for no displays', () => {
    expect(layoutDisplays([])).toEqual([]);
  });
});

describe('describing a display', () => {
  it('names resolution, refresh rate and scaling', () => {
    expect(describeDisplay(display(0, 0, 0, 2560, 1440, true, { refreshHz: 144, scaleFactor: 2 })))
      .toBe('2560×1440 · 144 Hz · 200%');
  });

  it('omits what the host did not report', () => {
    expect(describeDisplay(display(0, 0, 0, 1920, 1080, true, { refreshHz: null }))).toBe(
      '1920×1080',
    );
  });
});

describe('preferences', () => {
  function memoryStorage(): Storage {
    const map = new Map<string, string>();
    return {
      get length() {
        return map.size;
      },
      clear: () => {
        map.clear();
      },
      getItem: (key) => map.get(key) ?? null,
      key: (index) => [...map.keys()][index] ?? null,
      removeItem: (key) => {
        map.delete(key);
      },
      setItem: (key, value) => {
        map.set(key, value);
      },
    };
  }

  it('defaults to asking', () => {
    expect(loadPreferences(memoryStorage())).toEqual(DEFAULT_PREFERENCES);
    expect(DEFAULT_PREFERENCES.switchMode).toBe('ask');
  });

  it('round trips a saved choice', () => {
    const storage = memoryStorage();
    savePreferences({ switchMode: 'automatic', allDisplays: true }, storage);
    expect(loadPreferences(storage)).toEqual({ switchMode: 'automatic', allDisplays: true });
  });

  it('remembers never switching', () => {
    const storage = memoryStorage();
    savePreferences({ switchMode: 'never', allDisplays: false }, storage);
    expect(loadPreferences(storage).switchMode).toBe('never');
  });

  it('discards a corrupt value rather than repairing it', () => {
    const storage = memoryStorage();
    storage.setItem('rc.displayPreferences', '{not json');
    expect(loadPreferences(storage)).toEqual(DEFAULT_PREFERENCES);
  });

  it('discards a value with an unknown mode', () => {
    const storage = memoryStorage();
    storage.setItem('rc.displayPreferences', JSON.stringify({ switchMode: 'sometimes' }));
    expect(loadPreferences(storage)).toEqual(DEFAULT_PREFERENCES);
  });

  it('resets back to asking', () => {
    const storage = memoryStorage();
    savePreferences({ switchMode: 'automatic', allDisplays: false }, storage);
    expect(resetPreferences(storage)).toEqual(DEFAULT_PREFERENCES);
    expect(loadPreferences(storage)).toEqual(DEFAULT_PREFERENCES);
  });

  it('survives storage that throws', () => {
    // Private browsing or a full quota must not break a live session.
    const hostile: Storage = {
      length: 0,
      clear: () => {
        /* nothing is stored to clear */
      },
      getItem: () => {
        throw new Error('denied');
      },
      key: () => null,
      removeItem: () => {
        throw new Error('denied');
      },
      setItem: () => {
        throw new Error('denied');
      },
    };
    expect(loadPreferences(hostile)).toEqual(DEFAULT_PREFERENCES);
    expect(() => {
      savePreferences(DEFAULT_PREFERENCES, hostile);
    }).not.toThrow();
    expect(() => resetPreferences(hostile)).not.toThrow();
  });
});
