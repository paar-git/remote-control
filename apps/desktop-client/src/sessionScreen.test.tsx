import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type * as api from './api.js';
import type { ConnectionState } from './api.js';
import { SessionScreen } from './SessionScreen';
import * as inputApi from './inputApi.js';
import * as videoApi from './videoApi.js';

vi.mock('./api.js', async (importOriginal) => {
  const actual: typeof api = await importOriginal();
  return {
    ...actual,
    disconnectFromServer: vi.fn(() => Promise.resolve({ state: 'offline' })),
    pingServer: vi.fn(() => Promise.resolve(12)),
  };
});

vi.mock('./videoApi.js', async (importOriginal) => {
  const actual: typeof videoApi = await importOriginal();
  return {
    ...actual,
    startStream: vi.fn(() =>
      Promise.resolve({
        displayIndex: 0,
        codec: 'raw_rgba',
        width: 1920,
        height: 1080,
        hardwareAccelerated: false,
      }),
    ),
    stopStream: vi.fn(() => Promise.resolve(null)),
    listenStreamEnded: vi.fn(() => Promise.resolve(() => undefined)),
    listDisplays: vi.fn(() => Promise.resolve([])),
    requestKeyframe: vi.fn(() => Promise.resolve(null)),
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
    listenDisplays: vi.fn(() => Promise.resolve(() => undefined)),
  };
});

const CONNECTED: ConnectionState = {
  state: 'connected',
  sessionId: 'ses-1',
  address: '10.0.0.1:7443',
  permissions: ['view_screen'],
  deviceName: 'Office PC',
};

/** A session the other machine also granted control of. */
const CONTROLLING: ConnectionState = {
  state: 'connected',
  sessionId: 'ses-1',
  address: '10.0.0.1:7443',
  permissions: ['view_screen', 'control_input'],
  deviceName: 'Office PC',
};

function renderSession(): void {
  render(
    <SessionScreen
      connection={CONNECTED}
      deviceName="Office PC"
      permissions={['view_screen']}
      onToast={vi.fn()}
      onLeave={vi.fn()}
    />,
  );
}

describe('SessionScreen', () => {
  it('fit to window reaches the canvas, not just the button', async () => {
    // This toggle shipped dead once: it set state that only its own aria-pressed
    // read. Asserting the button's pressed state would not have caught that, so this
    // asserts the surface actually changes, not the control that requests the change.
    renderSession();
    const surface = await screen.findByTestId('video-surface');
    const fittedLayout = surface.parentElement?.className ?? '';

    await userEvent.click(screen.getByRole('button', { name: /fit to window/i }));

    const unfittedLayout = surface.parentElement?.className ?? '';
    expect(unfittedLayout).not.toBe(fittedLayout);
  });
});

describe('SessionScreen keyboard passthrough', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(inputApi.sendKey).mockResolvedValue({ asIntent: null });
  });

  /** A session that may actually drive the remote machine. */
  function renderControllingSession(): void {
    render(
      <SessionScreen
        connection={CONTROLLING}
        deviceName="Office PC"
        permissions={['view_screen', 'control_input']}
        onToast={vi.fn()}
        onLeave={vi.fn()}
      />,
    );
  }

  it('keyboard passthrough sends the literal chord instead of the intent', async () => {
    // Ctrl+C in a remote terminal is SIGINT. Without passthrough it is detected as Copy
    // and arrives as Cmd+C on a macOS host, so the operator can never interrupt.
    renderControllingSession();
    await userEvent.click(screen.getByRole('button', { name: /keyboard passthrough/i }));

    const surface = await screen.findByTestId('video-surface');
    surface.focus();
    await userEvent.keyboard('{Control>}c{/Control}');

    expect(inputApi.sendKey).toHaveBeenCalledWith(expect.objectContaining({ passthrough: true }));
  });

  it('sends chords for translation while passthrough is off', async () => {
    // The default has to stay translation, or every shortcut an operator knows breaks
    // the moment the two machines disagree about which modifier means "copy".
    renderControllingSession();

    const surface = await screen.findByTestId('video-surface');
    surface.focus();
    await userEvent.keyboard('{Control>}c{/Control}');

    expect(inputApi.sendKey).toHaveBeenCalledWith(expect.objectContaining({ passthrough: false }));
    expect(inputApi.sendKey).not.toHaveBeenCalledWith(
      expect.objectContaining({ passthrough: true }),
    );
  });

  it('says on screen that shortcuts are going through literally', async () => {
    // An operator who forgets the toggle is on will wonder why Copy stopped working.
    renderControllingSession();
    await screen.findByTestId('video-surface');

    await userEvent.click(screen.getByRole('button', { name: /keyboard passthrough/i }));

    expect(await screen.findByText(/sent literally/i)).toBeInTheDocument();
  });
});

/** Two side-by-side monitors, the second to the right of the first. */
const TWO_DISPLAYS = [
  {
    index: 0,
    name: 'Built-in',
    width: 1920,
    height: 1080,
    scaleFactor: 1,
    originX: 0,
    originY: 0,
    primary: true,
    refreshHz: 60,
  },
  {
    index: 1,
    name: 'DELL U2720Q',
    width: 3840,
    height: 2160,
    scaleFactor: 2,
    originX: 1920,
    originY: 0,
    primary: false,
    refreshHz: 60,
  },
];

describe('SessionScreen display picker', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(videoApi.listDisplays).mockResolvedValue(TWO_DISPLAYS);
    vi.mocked(inputApi.listenDisplays).mockResolvedValue(() => undefined);
  });

  it('offers a picker once the host reports more than one display', async () => {
    // listDisplays, DisplaySelector and useDisplayNavigation were all built, tested and
    // reachable from nothing. A session on a two-monitor host could only ever see one.
    renderSession();

    await userEvent.click(await screen.findByRole('button', { name: /displays/i }));

    expect(await screen.findByRole('group', { name: /remote displays/i })).toBeInTheDocument();
  });

  it('choosing a display streams that display', async () => {
    // The picker must reach the stream, not just its own pressed state — the same
    // defect Fit to window and Keyboard passthrough both shipped with.
    renderSession();
    await userEvent.click(await screen.findByRole('button', { name: /displays/i }));

    await userEvent.click(await screen.findByRole('button', { name: /DELL U2720Q/i }));

    await waitFor(() => {
      expect(videoApi.startStream).toHaveBeenCalledWith(
        1,
        expect.any(Number),
        expect.any(Function),
      );
    });
  });

  it('offers no picker when the host has a single display', async () => {
    // A picker that can only pick the thing already showing is chrome that never acts.
    vi.mocked(videoApi.listDisplays).mockResolvedValue([TWO_DISPLAYS[0]!]);
    renderSession();
    await screen.findByTestId('video-surface');

    expect(screen.queryByRole('button', { name: /displays/i })).not.toBeInTheDocument();
  });

  it('follows the host rearranging its monitors mid-session', async () => {
    // A monitor unplugged while a session is live changes where every later coordinate
    // lands; a picker that had to be reopened would aim at a layout that is gone.
    let push: ((displays: typeof TWO_DISPLAYS) => void) | undefined;
    vi.mocked(inputApi.listenDisplays).mockImplementation((handler) => {
      push = handler;
      return Promise.resolve(() => undefined);
    });

    renderSession();
    await userEvent.click(await screen.findByRole('button', { name: /displays/i }));
    await screen.findByRole('group', { name: /remote displays/i });

    act(() => {
      push?.([TWO_DISPLAYS[0]!]);
    });

    await waitFor(() => {
      expect(screen.queryByRole('button', { name: /displays/i })).not.toBeInTheDocument();
    });
  });
});

describe('SessionScreen refresh screen', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(videoApi.listDisplays).mockResolvedValue([]);
    vi.mocked(videoApi.requestKeyframe).mockResolvedValue(null);
  });

  it('refreshing the screen asks the host for a fresh keyframe', async () => {
    // requestKeyframe and its Tauri command existed with no caller. The reader repairs
    // itself on a *detected* sequence gap, which does nothing for a framebuffer that is
    // wrong but internally consistent — the case only a human notices.
    renderSession();

    await userEvent.click(await screen.findByRole('button', { name: /refresh screen/i }));

    await waitFor(() => {
      expect(videoApi.requestKeyframe).toHaveBeenCalled();
    });
  });

  it('says so when the host will not send one', async () => {
    // Silence here reads as "the tearing is permanent"; the operator would keep
    // clicking a button that already failed.
    const onToast = vi.fn();
    vi.mocked(videoApi.requestKeyframe).mockRejectedValue(new Error('no video stream is running'));
    render(
      <SessionScreen
        connection={CONNECTED}
        deviceName="Office PC"
        permissions={['view_screen']}
        onToast={onToast}
        onLeave={vi.fn()}
      />,
    );

    await userEvent.click(await screen.findByRole('button', { name: /refresh screen/i }));

    await waitFor(() => {
      expect(onToast).toHaveBeenCalledWith(
        expect.objectContaining({ kind: 'error', message: expect.stringMatching(/stream/i) }),
      );
    });
  });

  it('offers no refresh in a session that may not watch the screen', () => {
    // Absent, not disabled: there is nothing to refresh, and the toolbar's rule is that
    // a tool you may not use is not there.
    render(
      <SessionScreen
        connection={{ ...CONNECTED, state: 'connected', permissions: ['transfer_files'] }}
        deviceName="Office PC"
        permissions={['transfer_files']}
        onToast={vi.fn()}
        onLeave={vi.fn()}
      />,
    );

    expect(screen.queryByRole('button', { name: /refresh screen/i })).not.toBeInTheDocument();
  });
});
