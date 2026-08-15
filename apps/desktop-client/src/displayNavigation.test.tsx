import { act, render, renderHook, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import { DisplaySelector } from './DisplaySelector';
import { DisplaySwitchPrompt } from './DisplaySwitchPrompt';
import type { Crossing, RemoteDisplay } from './displays';
import { useDisplayNavigation } from './useDisplayNavigation';

/** A handler a test does not exercise. */
function noop(): void {
  // Deliberately empty: these tests assert rendering, not the callback.
}

function display(
  index: number,
  originX: number,
  originY: number,
  width = 1920,
  height = 1080,
  primary = false,
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
  };
}

const twoAcross = [display(0, 0, 0, 1920, 1080, true), display(1, 1920, 0)];
const tee = [
  display(0, 0, 0, 1920, 1080, true),
  display(1, 1920, 0),
  display(2, 960, -1080),
];

function memoryStorage(): Storage {
  const map = new Map<string, string>();
  return {
    get length() {
      return map.size;
    },
    clear: () => map.clear(),
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

describe('edge navigation', () => {
  it('starts on the primary display', () => {
    const { result } = renderHook(() => useDisplayNavigation(twoAcross, memoryStorage()));
    expect(result.current.active).toBe(0);
  });

  it('does nothing away from an edge', () => {
    const { result } = renderHook(() => useDisplayNavigation(twoAcross, memoryStorage()));
    act(() => {
      expect(result.current.onPointer(0.5, 0.5)).toBeNull();
    });
    expect(result.current.pending).toBeNull();
    expect(result.current.active).toBe(0);
  });

  it('does nothing at an edge with no display beyond it', () => {
    const { result } = renderHook(() => useDisplayNavigation(twoAcross, memoryStorage()));
    act(() => {
      // Left edge of the leftmost display.
      expect(result.current.onPointer(0, 0.5)).toBeNull();
    });
    expect(result.current.pending).toBeNull();
  });

  it('asks the first time an edge with a neighbour is reached', () => {
    const { result } = renderHook(() => useDisplayNavigation(twoAcross, memoryStorage()));
    act(() => {
      expect(result.current.onPointer(1, 0.6)).toBeNull();
    });
    expect(result.current.pending?.crossing.display).toBe(1);
    // Nothing moves until the operator answers.
    expect(result.current.active).toBe(0);
  });

  it('does not stack prompts while one is waiting', () => {
    const { result } = renderHook(() => useDisplayNavigation(twoAcross, memoryStorage()));
    act(() => {
      result.current.onPointer(1, 0.6);
    });
    const first = result.current.pending;
    act(() => {
      // Dragging along the edge must not queue more dialogs.
      result.current.onPointer(1, 0.61);
      result.current.onPointer(1, 0.62);
    });
    expect(result.current.pending).toBe(first);
  });

  it('moves when the operator says Move, preserving the position', () => {
    const { result } = renderHook(() => useDisplayNavigation(twoAcross, memoryStorage()));
    act(() => {
      result.current.onPointer(1, 0.6);
    });

    const captured: { value: Crossing | null } = { value: null };
    act(() => {
      captured.value = result.current.decide({ move: true, mode: null });
    });

    expect(result.current.active).toBe(1);
    expect(captured.value?.display).toBe(1);
    // Same height, not reset to the middle or a corner.
    expect(captured.value?.y).toBeCloseTo(0.6, 2);
    expect(result.current.pending).toBeNull();
  });

  it('stays put when the operator says Stay, and does not remember', () => {
    const storage = memoryStorage();
    const { result } = renderHook(() => useDisplayNavigation(twoAcross, storage));
    act(() => {
      result.current.onPointer(1, 0.5);
    });
    act(() => {
      expect(result.current.decide({ move: false, mode: null })).toBeNull();
    });
    expect(result.current.active).toBe(0);
    // A one-off answer must not become a preference.
    expect(result.current.preferences.switchMode).toBe('ask');

    // So it asks again next time.
    act(() => {
      result.current.onPointer(1, 0.5);
    });
    expect(result.current.pending).not.toBeNull();
  });

  it('stops asking once Always switch is chosen, and switches immediately after', () => {
    const storage = memoryStorage();
    const { result } = renderHook(() => useDisplayNavigation(twoAcross, storage));
    act(() => {
      result.current.onPointer(1, 0.5);
    });
    act(() => {
      result.current.decide({ move: true, mode: 'automatic' });
    });
    expect(result.current.active).toBe(1);
    expect(result.current.preferences.switchMode).toBe('automatic');

    // Coming back the other way must not prompt.
    const captured: { value: Crossing | null } = { value: null };
    act(() => {
      captured.value = result.current.onPointer(0, 0.4);
    });
    expect(result.current.pending).toBeNull();
    expect(result.current.active).toBe(0);
    expect(captured.value?.display).toBe(0);
  });

  it('never switches from an edge once Don’t ask again is chosen', () => {
    const storage = memoryStorage();
    const { result } = renderHook(() => useDisplayNavigation(twoAcross, storage));
    act(() => {
      result.current.onPointer(1, 0.5);
    });
    act(() => {
      result.current.decide({ move: false, mode: 'never' });
    });
    expect(result.current.preferences.switchMode).toBe('never');

    act(() => {
      expect(result.current.onPointer(1, 0.5)).toBeNull();
    });
    expect(result.current.pending).toBeNull();
    expect(result.current.active).toBe(0);
  });

  it('persists the choice across a remount', () => {
    const storage = memoryStorage();
    const first = renderHook(() => useDisplayNavigation(twoAcross, storage));
    act(() => {
      first.result.current.setPreferences({ switchMode: 'automatic', allDisplays: false });
    });
    first.unmount();

    const second = renderHook(() => useDisplayNavigation(twoAcross, storage));
    expect(second.result.current.preferences.switchMode).toBe('automatic');
  });

  it('still allows the picker after Never was chosen', () => {
    // "Never switch from the edge" is not "never change display".
    const storage = memoryStorage();
    const { result } = renderHook(() => useDisplayNavigation(twoAcross, storage));
    act(() => {
      result.current.setPreferences({ switchMode: 'never', allDisplays: false });
    });
    act(() => {
      result.current.select(1);
    });
    expect(result.current.active).toBe(1);
  });

  it('crosses to the display under the pointer when one spans two others', () => {
    const storage = memoryStorage();
    const { result } = renderHook(() => useDisplayNavigation(tee, storage));
    act(() => {
      result.current.setPreferences({ switchMode: 'automatic', allDisplays: false });
    });
    act(() => {
      result.current.select(2);
    });

    const captured: { value: Crossing | null } = { value: null };
    act(() => {
      captured.value = result.current.onPointer(0.9, 1);
    });
    expect(captured.value?.display).toBe(1);
  });
});

describe('display changes during a session', () => {
  it('follows to the primary when the viewed display is unplugged', () => {
    const { result, rerender } = renderHook(
      ({ displays }) => useDisplayNavigation(displays, memoryStorage()),
      { initialProps: { displays: twoAcross } },
    );
    act(() => {
      result.current.select(1);
    });
    expect(result.current.active).toBe(1);

    rerender({ displays: [twoAcross[0]!] });
    expect(result.current.active).toBe(0);
  });

  it('stays put when an unrelated display is added', () => {
    const { result, rerender } = renderHook(
      ({ displays }) => useDisplayNavigation(displays, memoryStorage()),
      { initialProps: { displays: twoAcross } },
    );
    act(() => {
      result.current.select(1);
    });
    rerender({ displays: tee });
    expect(result.current.active).toBe(1);
  });

  it('drops a pending prompt whose target disappeared', () => {
    const { result, rerender } = renderHook(
      ({ displays }) => useDisplayNavigation(displays, memoryStorage()),
      { initialProps: { displays: twoAcross } },
    );
    act(() => {
      result.current.onPointer(1, 0.5);
    });
    expect(result.current.pending).not.toBeNull();

    rerender({ displays: [twoAcross[0]!] });
    expect(result.current.pending).toBeNull();
  });
});

describe('the display selector', () => {
  it('is absent with a single display', () => {
    const { container } = render(
      <DisplaySelector displays={[twoAcross[0]!]} active={0} onSelect={noop} />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it('lists every display with its resolution', () => {
    render(<DisplaySelector displays={twoAcross} active={0} onSelect={noop} />);
    expect(screen.getByText('Display 1')).toBeInTheDocument();
    expect(screen.getAllByText('1920×1080 · 60 Hz').length).toBeGreaterThan(0);
  });

  it('marks the main display', () => {
    render(<DisplaySelector displays={twoAcross} active={0} onSelect={noop} />);
    expect(screen.getAllByText(/Main/).length).toBeGreaterThan(0);
  });

  it('selects a display when one is clicked', async () => {
    const onSelect = vi.fn();
    render(<DisplaySelector displays={twoAcross} active={0} onSelect={onSelect} />);
    // Each display is reachable from both the map and the list, so the list is
    // addressed explicitly rather than by a name both would match.
    const rows = screen.getAllByRole('listitem');
    await userEvent.click(rows[1]!.querySelector('button')!);
    expect(onSelect).toHaveBeenCalledWith(1);
  });

  it('shows which display is active', () => {
    render(<DisplaySelector displays={twoAcross} active={1} onSelect={noop} />);
    const pressed = screen
      .getAllByRole('button')
      .filter((button) => button.getAttribute('aria-pressed') === 'true');
    expect(pressed.length).toBeGreaterThan(0);
  });

  it('draws the arrangement rather than a row', () => {
    // The monitor above must render above, not beside.
    render(<DisplaySelector displays={tee} active={0} onSelect={noop} />);
    const group = screen.getByRole('group', { name: 'Remote displays' });
    const tiles = [...group.querySelectorAll('button')];
    const tops = tiles.map((tile) => Number.parseFloat(tile.style.top));
    expect(Math.min(...tops)).toBeCloseTo(0);
    expect(Math.max(...tops)).toBeGreaterThan(0);
  });
});

describe('the switch prompt', () => {
  it('names the display it would move to', () => {
    render(<DisplaySwitchPrompt target={twoAcross[1]!} onDecide={noop} />);
    expect(screen.getByText(/Move to Display 2/)).toBeInTheDocument();
  });

  it('offers all four answers', () => {
    render(<DisplaySwitchPrompt target={twoAcross[1]!} onDecide={noop} />);
    for (const label of ['Move', 'Stay', 'Always switch', 'Don’t ask again']) {
      expect(screen.getByRole('button', { name: label })).toBeInTheDocument();
    }
  });

  it('reports a one-off move', async () => {
    const onDecide = vi.fn();
    render(<DisplaySwitchPrompt target={twoAcross[1]!} onDecide={onDecide} />);
    await userEvent.click(screen.getByRole('button', { name: 'Move' }));
    expect(onDecide).toHaveBeenCalledWith({ move: true, mode: null });
  });

  it('reports a durable automatic choice', async () => {
    const onDecide = vi.fn();
    render(<DisplaySwitchPrompt target={twoAcross[1]!} onDecide={onDecide} />);
    await userEvent.click(screen.getByRole('button', { name: 'Always switch' }));
    expect(onDecide).toHaveBeenCalledWith({ move: true, mode: 'automatic' });
  });

  it('reports a durable refusal', async () => {
    const onDecide = vi.fn();
    render(<DisplaySwitchPrompt target={twoAcross[1]!} onDecide={onDecide} />);
    await userEvent.click(screen.getByRole('button', { name: 'Don’t ask again' }));
    expect(onDecide).toHaveBeenCalledWith({ move: false, mode: 'never' });
  });
});
