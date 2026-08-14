import { invoke } from '@tauri-apps/api/core';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { MainWindow } from './MainWindow';

const invoked = vi.mocked(invoke);

/** Backend answers for one render. Anything not listed is an unexpected call. */
function identity() {
  return {
    deviceId: 'dev_1f0c9a2b-3d4e-4f5a-8b6c-7d8e9f0a1b2c',
    identityFingerprint: 'a'.repeat(64),
    certificateFingerprint: 'b'.repeat(64),
    certificateVersion: 1,
    certificateNotBeforeMs: 1,
    certificateNotAfterMs: 2,
    needsRenewal: false,
  };
}

function backend(
  overrides: {
    accepting?: boolean;
    addresses?: string[];
    recent?: unknown[];
    connect?: () => unknown;
  } = {},
) {
  invoked.mockImplementation((command: string, args?: unknown) => {
    switch (command) {
      case 'host_status':
        return Promise.resolve({
          accepting: overrides.accepting ?? true,
          addresses: overrides.addresses ?? ['192.168.1.42:7443'],
          machineName: 'KOREN-PC',
          listenPort: 7443,
        });
      case 'list_recent':
        return Promise.resolve(overrides.recent ?? []);
      case 'local_identity':
        return Promise.resolve(identity());
      case 'client_info':
        return Promise.resolve({
          appVersion: '0.2.0',
          protocolVersion: { major: 1, minor: 0 },
          hostname: 'KOREN-PC',
          osFamily: 'windows',
          osVersion: '10.0',
          architecture: 'x86_64',
          elevated: false,
          databaseReady: true,
        });
      case 'set_accepting': {
        const accepting = (args as { accepting: boolean }).accepting;
        return Promise.resolve({
          accepting,
          addresses: overrides.addresses ?? ['192.168.1.42:7443'],
          machineName: 'KOREN-PC',
          listenPort: 7443,
        });
      }
      case 'connect_to_address':
        return Promise.resolve(
          overrides.connect?.() ?? {
            state: 'connected',
            sessionId: 's1',
            address: '192.168.1.77:7443',
          },
        );
      default:
        return Promise.reject(new Error(`unexpected command ${command}`));
    }
  });
}

function recentEntry(overrides: Record<string, unknown> = {}) {
  return {
    address: '192.168.1.77:7443',
    machineName: 'WORK-LAPTOP',
    lastConnectedMs: Date.now() - 60_000,
    alwaysAllow: false,
    pinnedPermissions: [],
    ...overrides,
  };
}

function renderWindow() {
  return render(
    <MainWindow
      onConnected={vi.fn()}
      onToast={vi.fn()}
      onOpenSettings={vi.fn()}
      connection={{ state: 'offline' }}
    />,
  );
}

describe('MainWindow', () => {
  beforeEach(() => {
    invoked.mockReset();
  });

  it('hides raw addresses until advanced network info is opened', async () => {
    backend({ addresses: ['192.168.1.42:7443', '10.0.0.5:7443'] });
    const user = userEvent.setup();
    renderWindow();

    expect(await screen.findByText('KOREN-PC')).toBeInTheDocument();
    expect(screen.queryByText('192.168.1.42')).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /advanced network info/i }));
    expect(await screen.findByText('192.168.1.42')).toBeInTheDocument();
    expect(screen.getByText('10.0.0.5')).toBeInTheDocument();
  });

  it('says it is ready when incoming connections are allowed', async () => {
    backend({ accepting: true });
    renderWindow();

    expect(await screen.findByText(/^Ready for connections$/)).toBeInTheDocument();
    expect(screen.getByRole('switch', { name: /allow incoming connections/i })).toHaveAttribute(
      'aria-checked',
      'true',
    );
  });

  it('says it is not accepting when incoming connections are off', async () => {
    backend({ accepting: false });
    renderWindow();

    expect(await screen.findByText(/^Not accepting connections$/)).toBeInTheDocument();
    expect(screen.getByRole('switch', { name: /allow incoming connections/i })).toHaveAttribute(
      'aria-checked',
      'false',
    );
  });

  it('shows nothing rather than a placeholder when no address could be determined', async () => {
    backend({ addresses: [] });
    const user = userEvent.setup();
    renderWindow();

    await user.click(await screen.findByRole('button', { name: /advanced network info/i }));
    expect(await screen.findByText(/no network address/i)).toBeInTheDocument();
  });

  it('reports an invalid address under the field and keeps what was typed', async () => {
    // Clearing the field would throw away the thing the user needs to correct.
    backend();
    const user = userEvent.setup();
    renderWindow();

    const field = await screen.findByLabelText(/device id, hostname, or ip/i);
    await user.type(field, 'https://192.168.1.77');
    await user.click(screen.getByRole('button', { name: /^connect$/i }));

    expect(await screen.findByText(/not a web address/i)).toBeInTheDocument();
    expect(field).toHaveValue('https://192.168.1.77');
    expect(invoked).not.toHaveBeenCalledWith('connect_to_address', expect.anything());
  });

  it('connects once, with the canonical form of what was typed', async () => {
    backend();
    const user = userEvent.setup();
    renderWindow();

    const field = await screen.findByLabelText(/device id, hostname, or ip/i);
    // Typed without a port and with stray whitespace; the backend must receive neither.
    await user.type(field, '  192.168.1.77  ');
    await user.click(screen.getByRole('button', { name: /^connect$/i }));

    await waitFor(() => {
      expect(invoked).toHaveBeenCalledWith('connect_to_address', {
        address: '192.168.1.77:7443',
        unattendedPassword: null,
      });
    });
    expect(invoked.mock.calls.filter(([command]) => command === 'connect_to_address')).toHaveLength(
      1,
    );
  });

  it('renders a one-sentence empty state rather than a bare list', async () => {
    backend({ recent: [] });
    renderWindow();

    expect(await screen.findByText(/no recent devices/i)).toBeInTheDocument();
  });

  it('shows a recent machine with its name, address and when it was last reached', async () => {
    backend({ recent: [recentEntry()] });
    renderWindow();

    expect((await screen.findAllByText('WORK-LAPTOP')).length).toBeGreaterThan(0);
    expect(screen.getByText(/192\.168\.1\.77/)).toBeInTheDocument();
    expect(screen.getByText(/ago$/)).toBeInTheDocument();
  });

  it('connects to a recent machine when its row is clicked', async () => {
    backend({ recent: [recentEntry()] });
    const user = userEvent.setup();
    renderWindow();

    await user.click((await screen.findAllByRole('button', { name: 'WORK-LAPTOP' }))[0]!);

    await waitFor(() => {
      expect(invoked).toHaveBeenCalledWith('connect_to_address', {
        address: '192.168.1.77:7443',
        unattendedPassword: null,
      });
    });
  });

  it('renders an untrusted machine name without its bidi override', async () => {
    // The name comes from the other machine. Rendered raw, `WORK<U+202E>POTAL` displays
    // as `WORKLATOP` — a different machine's name, chosen by the peer.
    backend({ recent: [recentEntry({ machineName: 'WORK‮POTAL' })] });
    renderWindow();

    expect((await screen.findAllByText('WORKPOTAL')).length).toBeGreaterThan(0);
  });

  it('surfaces a refusal rather than leaving the button spinning', async () => {
    backend({
      connect: () => {
        throw new Error('The other machine did not accept this connection.');
      },
    });
    const user = userEvent.setup();
    renderWindow();

    const field = await screen.findByLabelText(/device id, hostname, or ip/i);
    await user.type(field, '192.168.1.77');
    await user.click(screen.getByRole('button', { name: /^connect$/i }));

    expect(await screen.findByText(/did not accept/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^connect$/i })).toBeEnabled();
  });
});
