import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import type * as api from './api.js';
import type { ConnectionState } from './api.js';
import { SessionScreen } from './SessionScreen';
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

const CONNECTED: ConnectionState = {
  state: 'connected',
  sessionId: 'ses-1',
  address: '10.0.0.1:7443',
  permissions: ['view_screen'],
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
