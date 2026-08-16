import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import * as inputApi from './inputApi.js';
import * as videoApi from './videoApi.js';
import { VideoSurface } from './VideoSurface';

vi.mock('./videoApi.js', async (importOriginal) => {
  const actual: typeof videoApi = await importOriginal();
  return {
    ...actual,
    startStream: vi.fn(),
    stopStream: vi.fn(() => Promise.resolve(null)),
    requestKeyframe: vi.fn(() => Promise.resolve(null)),
    listenStreamEnded: vi.fn(() => Promise.resolve(() => undefined)),
  };
});

vi.mock('./inputApi.js', async (importOriginal) => {
  const actual: typeof inputApi = await importOriginal();
  return {
    ...actual,
    sendKey: vi.fn(() => Promise.resolve({ asIntent: null })),
    sendPointerMove: vi.fn(() => Promise.resolve(null)),
    sendPointerButton: vi.fn(() => Promise.resolve(null)),
    sendScroll: vi.fn(() => Promise.resolve(null)),
  };
});

const STARTED: videoApi.StreamStarted = {
  displayIndex: 0,
  codec: 'raw_rgba',
  width: 1920,
  height: 1080,
  hardwareAccelerated: false,
};

describe('VideoSurface', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(videoApi.startStream).mockImplementation((displayIndex) => {
      // Display 9 stands in for "the agent refused" — every other index starts fine.
      if (displayIndex === 9) {
        return Promise.reject(new Error('Could not start capturing that display.'));
      }
      return Promise.resolve(STARTED);
    });
  });

  it('sizes the canvas to the stream the agent actually started', async () => {
    // A canvas left at its default size silently scales every frame, which reads as
    // a blurry remote rather than as a bug in this component.
    render(<VideoSurface displayIndex={0} fitted capturing={false} />);

    const canvas = await screen.findByTestId<HTMLCanvasElement>('video-surface');
    await waitFor(() => {
      expect(canvas.width).toBe(1920);
      expect(canvas.height).toBe(1080);
    });
  });

  it('says the stream failed rather than showing an empty black rectangle', async () => {
    // Indistinguishable states are the failure this project keeps guarding against:
    // a black canvas could be a locked remote screen or a dead stream.
    render(<VideoSurface displayIndex={9} fitted capturing={false} />);
    expect(await screen.findByRole('alert')).toHaveTextContent(/could not start/i);
  });

  it('says the stream failed when it dies mid-session, not just at start', async () => {
    // Otherwise a stream that dies after starting looks identical to a screen where
    // nothing is happening.
    let endStream: ((ended: videoApi.StreamEnded) => void) | undefined;
    vi.mocked(videoApi.listenStreamEnded).mockImplementation((handler) => {
      endStream = handler;
      return Promise.resolve(() => undefined);
    });

    render(<VideoSurface displayIndex={0} fitted capturing={false} />);
    await screen.findByTestId('video-surface');

    await waitFor(() => {
      expect(endStream).toBeDefined();
    });
    endStream?.({
      code: 'channel_closed',
      message: 'The connection to the other device was lost.',
    });

    expect(await screen.findByRole('alert')).toHaveTextContent(/connection.*lost/i);
  });
});

describe('VideoSurface input capture', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(videoApi.startStream).mockResolvedValue(STARTED);
    vi.mocked(videoApi.listenStreamEnded).mockResolvedValue(() => undefined);
  });

  /** Render a capturing surface and hand back its focused canvas. */
  async function focusedSurface(): Promise<HTMLCanvasElement> {
    render(<VideoSurface displayIndex={0} fitted capturing />);
    const canvas = await screen.findByTestId<HTMLCanvasElement>('video-surface');
    canvas.focus();
    return canvas;
  }

  it('forwards a keystroke to the remote machine once focused', async () => {
    const canvas = await focusedSurface();
    await userEvent.type(canvas, 'a');

    expect(inputApi.sendKey).toHaveBeenCalledWith(
      expect.objectContaining({ code: 'KeyA', down: true }),
    );
  });

  it('sends nothing at all while capture is off', async () => {
    // A session where the operator has not taken control must not leak their typing to
    // the remote machine.
    render(<VideoSurface displayIndex={0} fitted capturing={false} />);
    const canvas = await screen.findByTestId<HTMLCanvasElement>('video-surface');
    canvas.focus();
    await userEvent.type(canvas, 'a');

    expect(inputApi.sendKey).not.toHaveBeenCalled();
  });

  it('is not a tab stop while capture is off', async () => {
    // A surface that takes focus but forwards nothing is a keyboard trap for anyone
    // tabbing through the session screen.
    render(<VideoSurface displayIndex={0} fitted capturing={false} />);
    const canvas = await screen.findByTestId('video-surface');
    expect(canvas).not.toHaveAttribute('tabindex');
  });

  it('releases a key still held when the surface loses focus', async () => {
    // The host has no other way to learn the key came up, and would repeat it forever.
    const canvas = await focusedSurface();
    await userEvent.keyboard('{a>}');
    vi.mocked(inputApi.sendKey).mockClear();

    canvas.blur();

    expect(inputApi.sendKey).toHaveBeenCalledWith(
      expect.objectContaining({ code: 'KeyA', down: false }),
    );
  });

  it('releases a key still held when the session unmounts mid-chord', async () => {
    // Closing the session while holding a key is the one exit no event reports.
    const { unmount } = render(<VideoSurface displayIndex={0} fitted capturing />);
    const canvas = await screen.findByTestId<HTMLCanvasElement>('video-surface');
    canvas.focus();
    await userEvent.keyboard('{Shift>}');
    vi.mocked(inputApi.sendKey).mockClear();

    unmount();

    expect(inputApi.sendKey).toHaveBeenCalledWith(
      expect.objectContaining({ code: 'ShiftLeft', down: false }),
    );
  });

  it('sends a click as a named button', async () => {
    const canvas = await focusedSurface();
    await userEvent.click(canvas);

    expect(inputApi.sendPointerButton).toHaveBeenCalledWith('left', true);
    expect(inputApi.sendPointerButton).toHaveBeenCalledWith('left', false);
  });

  it('sends the pointer as a fraction, never as pixels', async () => {
    // jsdom reports a zero-sized rect, which must still be a number the host can use.
    const canvas = await focusedSurface();
    await userEvent.click(canvas);

    expect(inputApi.sendPointerMove).toHaveBeenCalledWith(
      expect.any(Number),
      expect.any(Number),
      0,
    );
    const [x, y] = vi.mocked(inputApi.sendPointerMove).mock.calls[0] ?? [];
    expect(Number.isNaN(x)).toBe(false);
    expect(Number.isNaN(y)).toBe(false);
  });
});
