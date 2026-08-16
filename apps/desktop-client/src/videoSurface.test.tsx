import { act, render, screen, waitFor } from '@testing-library/react';
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
    listenClipboard: vi.fn(() => Promise.resolve(() => undefined)),
    sendClipboard: vi.fn(() => Promise.resolve(null)),
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
    listenInputAck: vi.fn(() => Promise.resolve(() => undefined)),
    listenInputApplied: vi.fn(() => Promise.resolve(() => undefined)),
    setKeyGrab: vi.fn(() => Promise.resolve(false)),
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
    render(<VideoSurface displayIndex={0} fitted capturing={false} passthrough={false} onPointerSample={() => null} sharingClipboard={false} />);

    const canvas = await screen.findByTestId<HTMLCanvasElement>('video-surface');
    await waitFor(() => {
      expect(canvas.width).toBe(1920);
      expect(canvas.height).toBe(1080);
    });
  });

  it('says the stream failed rather than showing an empty black rectangle', async () => {
    // Indistinguishable states are the failure this project keeps guarding against:
    // a black canvas could be a locked remote screen or a dead stream.
    render(<VideoSurface displayIndex={9} fitted capturing={false} passthrough={false} onPointerSample={() => null} sharingClipboard={false} />);
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

    render(<VideoSurface displayIndex={0} fitted capturing={false} passthrough={false} onPointerSample={() => null} sharingClipboard={false} />);
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
    render(<VideoSurface displayIndex={0} fitted capturing passthrough={false} onPointerSample={() => null} sharingClipboard={false} />);
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
    render(<VideoSurface displayIndex={0} fitted capturing={false} passthrough={false} onPointerSample={() => null} sharingClipboard={false} />);
    const canvas = await screen.findByTestId<HTMLCanvasElement>('video-surface');
    canvas.focus();
    await userEvent.type(canvas, 'a');

    expect(inputApi.sendKey).not.toHaveBeenCalled();
  });

  it('is not a tab stop while capture is off', async () => {
    // A surface that takes focus but forwards nothing is a keyboard trap for anyone
    // tabbing through the session screen.
    render(<VideoSurface displayIndex={0} fitted capturing={false} passthrough={false} onPointerSample={() => null} sharingClipboard={false} />);
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
    const { unmount } = render(<VideoSurface displayIndex={0} fitted capturing passthrough={false} onPointerSample={() => null} sharingClipboard={false} />);
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

describe('VideoSurface refused input', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(videoApi.startStream).mockResolvedValue(STARTED);
    vi.mocked(videoApi.listenStreamEnded).mockResolvedValue(() => undefined);
  });

  /** Render a capturing surface and hand back the ack handler it registered. */
  async function surfaceWithAcks(): Promise<(ack: inputApi.InputAck) => void> {
    let deliver: ((ack: inputApi.InputAck) => void) | undefined;
    vi.mocked(inputApi.listenInputAck).mockImplementation((handler) => {
      deliver = handler;
      return Promise.resolve(() => undefined);
    });

    render(<VideoSurface displayIndex={0} fitted capturing passthrough={false} onPointerSample={() => null} sharingClipboard={false} />);
    await screen.findByTestId('video-surface');
    await waitFor(() => {
      expect(deliver).toBeDefined();
    });
    return deliver as (ack: inputApi.InputAck) => void;
  }

  it('says the host refused the input instead of looking frozen', async () => {
    // A revoked control_input grant is otherwise indistinguishable from a remote
    // machine that has simply stopped responding.
    const deliver = await surfaceWithAcks();

    act(() => {
      deliver({ seq: 3, ok: false, reason: 'this session may not control the host' });
    });

    expect(await screen.findByRole('status')).toHaveTextContent(/may not control the host/i);
  });

  it('stops saying so once the host accepts input again', async () => {
    // A permission restored mid-session must clear the warning, or the operator is
    // told they cannot type while they can.
    const deliver = await surfaceWithAcks();
    act(() => {
      deliver({ seq: 3, ok: false, reason: 'this session may not control the host' });
    });
    await screen.findByRole('status');

    act(() => {
      deliver({ seq: 4, ok: true, reason: null });
    });

    await waitFor(() => {
      expect(screen.queryByText(/may not control the host/i)).not.toBeInTheDocument();
    });
  });

  it('does not listen for acknowledgements while capture is off', async () => {
    // Nothing is being sent, so nothing can be refused; a warning here would be noise.
    render(<VideoSurface displayIndex={0} fitted capturing={false} passthrough={false} onPointerSample={() => null} sharingClipboard={false} />);
    await screen.findByTestId('video-surface');

    expect(inputApi.listenInputAck).not.toHaveBeenCalled();
  });
});

describe('VideoSurface display crossing', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(videoApi.startStream).mockResolvedValue(STARTED);
    vi.mocked(videoApi.listenStreamEnded).mockResolvedValue(() => undefined);
    vi.mocked(inputApi.listenInputAck).mockResolvedValue(() => undefined);
  });

  it('sends the pointer to the neighbouring display when it crosses an edge', async () => {
    // The operator's hand does not stop at the seam between two monitors, so neither
    // should the cursor: the crossing lands on the *other* display, not display 0.
    const crossing = { display: 1, x: 0.01, y: 0.42 };
    render(
      <VideoSurface
        displayIndex={0}
        fitted
        capturing
        passthrough={false}
        sharingClipboard={false}
        onPointerSample={() => crossing}
      />,
    );
    const canvas = await screen.findByTestId<HTMLCanvasElement>('video-surface');
    canvas.focus();
    await userEvent.click(canvas);

    expect(inputApi.sendPointerMove).toHaveBeenCalledWith(0.01, 0.42, 1);
  });

  it('stays on the current display when no edge was reached', async () => {
    render(
      <VideoSurface
        displayIndex={0}
        fitted
        capturing
        passthrough={false}
        sharingClipboard={false}
        onPointerSample={() => null}
      />,
    );
    const canvas = await screen.findByTestId<HTMLCanvasElement>('video-surface');
    canvas.focus();
    await userEvent.click(canvas);

    expect(inputApi.sendPointerMove).toHaveBeenCalledWith(expect.any(Number), expect.any(Number), 0);
  });
});

describe('VideoSurface input lag', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(videoApi.startStream).mockResolvedValue(STARTED);
    vi.mocked(videoApi.listenStreamEnded).mockResolvedValue(() => undefined);
    vi.mocked(inputApi.listenInputAck).mockResolvedValue(() => undefined);
  });

  /** Render a capturing surface and hand back the applied-watermark handler. */
  async function surfaceWithWatermark(): Promise<(applied: inputApi.InputApplied) => void> {
    let deliver: ((applied: inputApi.InputApplied) => void) | undefined;
    vi.mocked(inputApi.listenInputApplied).mockImplementation((handler) => {
      deliver = handler;
      return Promise.resolve(() => undefined);
    });

    render(
      <VideoSurface
        displayIndex={0}
        fitted
        capturing
        passthrough={false}
        sharingClipboard={false}
        onPointerSample={() => null}
      />,
    );
    await screen.findByTestId('video-surface');
    await waitFor(() => {
      expect(deliver).toBeDefined();
    });
    return deliver as (applied: inputApi.InputApplied) => void;
  }

  it('says the remote machine is behind when it stops keeping up', async () => {
    // A host too busy to apply input looks, from here, exactly like one that has
    // stopped — and the link's own ping stays healthy throughout.
    const deliver = await surfaceWithWatermark();

    act(() => {
      deliver({ watermark: 10, outstanding: 200 });
    });

    expect(await screen.findByRole('status')).toHaveTextContent(/behind/i);
  });

  it('stays quiet while the host keeps up', async () => {
    // A few events in flight is the normal state of a live session, not a warning.
    const deliver = await surfaceWithWatermark();

    act(() => {
      deliver({ watermark: 100, outstanding: 2 });
    });

    await waitFor(() => {
      expect(screen.queryByText(/behind/i)).not.toBeInTheDocument();
    });
  });
});

describe('VideoSurface clipboard', () => {
  // Held as values rather than reached through `navigator.clipboard` at assertion time:
  // reading a method off an object and passing it around loses its `this`.
  let readText: ReturnType<typeof vi.fn>;
  let writeText: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(videoApi.startStream).mockResolvedValue(STARTED);
    vi.mocked(videoApi.listenStreamEnded).mockResolvedValue(() => undefined);
    vi.mocked(inputApi.listenInputAck).mockResolvedValue(() => undefined);
    vi.mocked(inputApi.listenInputApplied).mockResolvedValue(() => undefined);
    vi.mocked(videoApi.listenClipboard).mockResolvedValue(() => undefined);
    readText = vi.fn(() => Promise.resolve('copied here'));
    writeText = vi.fn(() => Promise.resolve());
    Object.assign(navigator, { clipboard: { readText, writeText } });
  });

  /** A sharing surface, and the handler it registered for host clipboard pushes. */
  async function sharingSurface(): Promise<{
    canvas: HTMLCanvasElement;
    push: (text: string) => void;
  }> {
    let deliver: ((text: string) => void) | undefined;
    vi.mocked(videoApi.listenClipboard).mockImplementation((handler) => {
      deliver = handler;
      return Promise.resolve(() => undefined);
    });

    render(
      <VideoSurface
        displayIndex={0}
        fitted
        capturing
        passthrough={false}
        sharingClipboard
        onPointerSample={() => null}
      />,
    );
    const canvas = await screen.findByTestId<HTMLCanvasElement>('video-surface');
    await waitFor(() => {
      expect(deliver).toBeDefined();
    });
    return { canvas, push: deliver as (text: string) => void };
  }

  it('writes text the host published onto this machine', async () => {
    const { push } = await sharingSurface();

    act(() => {
      push('from the remote machine');
    });

    await waitFor(() => {
      expect(writeText).toHaveBeenCalledWith('from the remote machine');
    });
  });

  it('does not publish back what the host just sent', async () => {
    // The echo. Both ends hold this state; either one alone still lets the other bounce
    // the value back forever.
    const { canvas, push } = await sharingSurface();
    act(() => {
      push('round trip');
    });
    readText.mockResolvedValue('round trip');

    canvas.focus();

    await waitFor(() => {
      expect(readText).toHaveBeenCalled();
    });
    expect(videoApi.sendClipboard).not.toHaveBeenCalled();
  });

  it("publishes this machine's clipboard when the operator turns to the remote screen", async () => {
    const { canvas } = await sharingSurface();

    canvas.focus();

    await waitFor(() => {
      expect(videoApi.sendClipboard).toHaveBeenCalledWith('copied here');
    });
  });

  it('shares nothing at all when the session was not granted the clipboard', async () => {
    // The grant is the whole gate on this side: a session without it must not read the
    // operator's clipboard, let alone send it.
    render(
      <VideoSurface
        displayIndex={0}
        fitted
        capturing
        passthrough={false}
        sharingClipboard={false}
        onPointerSample={() => null}
      />,
    );
    const canvas = await screen.findByTestId<HTMLCanvasElement>('video-surface');
    canvas.focus();

    expect(videoApi.listenClipboard).not.toHaveBeenCalled();
    expect(readText).not.toHaveBeenCalled();
    expect(videoApi.sendClipboard).not.toHaveBeenCalled();
  });
});

describe('VideoSurface desktop shortcut grab', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(videoApi.startStream).mockResolvedValue(STARTED);
    vi.mocked(videoApi.listenStreamEnded).mockResolvedValue(() => undefined);
    vi.mocked(inputApi.listenInputAck).mockResolvedValue(() => undefined);
    vi.mocked(inputApi.listenInputApplied).mockResolvedValue(() => undefined);
    vi.mocked(inputApi.setKeyGrab).mockResolvedValue(true);
  });

  it('asks for the local Alt+Tab only once focused and forwarding', async () => {
    render(
      <VideoSurface
        displayIndex={0}
        fitted
        capturing
        passthrough={false}
        sharingClipboard={false}
        onPointerSample={() => null}
      />,
    );
    const canvas = await screen.findByTestId<HTMLCanvasElement>('video-surface');
    await waitFor(() => {
      expect(inputApi.setKeyGrab).toHaveBeenCalledWith(false, true);
    });

    canvas.focus();

    await waitFor(() => {
      expect(inputApi.setKeyGrab).toHaveBeenCalledWith(true, true);
    });
  });

  it('hands the shortcuts back the moment focus is lost', async () => {
    // Holding the operator's Alt+Tab while they work on their own machine would be a
    // serious bug, so the release runs on every change rather than only on teardown.
    render(
      <VideoSurface
        displayIndex={0}
        fitted
        capturing
        passthrough={false}
        sharingClipboard={false}
        onPointerSample={() => null}
      />,
    );
    const canvas = await screen.findByTestId<HTMLCanvasElement>('video-surface');
    canvas.focus();
    await waitFor(() => {
      expect(inputApi.setKeyGrab).toHaveBeenCalledWith(true, true);
    });
    vi.mocked(inputApi.setKeyGrab).mockClear();

    canvas.blur();

    await waitFor(() => {
      expect(inputApi.setKeyGrab).toHaveBeenCalledWith(false, true);
    });
  });

  it('never asks for a grab in a session that forwards no input', async () => {
    render(
      <VideoSurface
        displayIndex={0}
        fitted
        capturing={false}
        passthrough={false}
        sharingClipboard={false}
        onPointerSample={() => null}
      />,
    );
    const canvas = await screen.findByTestId<HTMLCanvasElement>('video-surface');
    canvas.focus();

    await waitFor(() => {
      expect(inputApi.setKeyGrab).toHaveBeenCalled();
    });
    expect(inputApi.setKeyGrab).not.toHaveBeenCalledWith(expect.anything(), true);
  });
});
