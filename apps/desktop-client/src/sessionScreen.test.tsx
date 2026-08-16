import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type * as api from './api.js';
import type { ConnectionState } from './api.js';
import { SessionScreen } from './SessionScreen';
import * as inputApi from './inputApi.js';
import type * as videoApi from './videoApi.js';

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
