import { invoke } from '@tauri-apps/api/core';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { MainWindow } from './MainWindow';

const invoked = vi.mocked(invoke);

/** Backend answers for one render. Anything not listed is an unexpected call. */
function backend(
  overrides: {
    accepting?: boolean;
    addresses?: string[];
    recent?: unknown[];
    connect?: () => unknown;
  } = {},
) {
  invoked.mockImplementation((command: string) => {
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
  return render(<MainWindow onConnected={vi.fn()} onToast={vi.fn()} onOpenSettings={vi.fn()} />);
}

describe('MainWindow', () => {
  beforeEach(() => {
    invoked.mockReset();
  });

  it('renders each address this machine can be reached on', async () => {
    backend({ addresses: ['192.168.1.42:7443', '10.0.0.5:7443'] });
    renderWindow();

    expect(await screen.findByText('192.168.1.42')).toBeInTheDocument();
    expect(screen.getByText('10.0.0.5')).toBeInTheDocument();
    // One copy control per address, so a user can hand either one over.
    expect(screen.getAllByRole('button', { name: /copy/i })).toHaveLength(2);
  });

  it('says it is accepting connections when it is', async () => {
    backend({ accepting: true });
    renderWindow();

    expect(await screen.findByText(/^Accepting connections$/)).toBeInTheDocument();
  });

  it('says it is not accepting connections when it is not', async () => {
    // The dangerous direction to get wrong: someone who believes they are reachable
    // and is not will wait for a connection that can never arrive.
    backend({ accepting: false });
    renderWindow();

    expect(await screen.findByText(/^Not accepting connections$/)).toBeInTheDocument();
  });

  it('shows nothing rather than a placeholder when no address could be determined', async () => {
    // A machine with no network gets an honest empty state, never a fake address.
    backend({ addresses: [] });
    renderWindow();

    expect(await screen.findByText(/no network address/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /copy/i })).not.toBeInTheDocument();
  });

  it('reports an invalid address under the field and keeps what was typed', async () => {
    // Clearing the field would throw away the thing the user needs to correct.
    backend();
    const user = userEvent.setup();
    renderWindow();

    const field = await screen.findByLabelText(/address/i);
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

    const field = await screen.findByLabelText(/address/i);
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

    expect(
      await screen.findByText(/machines you connect to will appear here/i),
    ).toBeInTheDocument();
  });

  it('shows a recent machine with its name, address and when it was last reached', async () => {
    backend({ recent: [recentEntry()] });
    renderWindow();

    expect(await screen.findByText('WORK-LAPTOP')).toBeInTheDocument();
    expect(screen.getByText('192.168.1.77')).toBeInTheDocument();
    expect(screen.getByText(/ago$/)).toBeInTheDocument();
  });

  it('connects to a recent machine when its row is clicked', async () => {
    backend({ recent: [recentEntry()] });
    const user = userEvent.setup();
    renderWindow();

    await user.click(await screen.findByRole('button', { name: /WORK-LAPTOP/ }));

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

    expect(await screen.findByText('WORKPOTAL')).toBeInTheDocument();
  });

  it('surfaces a refusal rather than leaving the button spinning', async () => {
    backend({
      connect: () => {
        throw new Error('The other machine did not accept this connection.');
      },
    });
    const user = userEvent.setup();
    renderWindow();

    const field = await screen.findByLabelText(/address/i);
    await user.type(field, '192.168.1.77');
    await user.click(screen.getByRole('button', { name: /^connect$/i }));

    expect(await screen.findByText(/did not accept/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^connect$/i })).toBeEnabled();
  });
});
