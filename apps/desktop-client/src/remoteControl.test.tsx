import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { ConnectionState } from './api.js';
import * as api from './api.js';
import { RemoteControlPage } from './RemoteControlPage';

vi.mock('./api.js', async (importOriginal) => {
  const actual: typeof api = await importOriginal();
  return {
    ...actual,
    connectToAddress: vi.fn(() => Promise.resolve({ state: 'connecting', address: 'x' })),
    getHostStatus: vi.fn(),
    getLocalIdentity: vi.fn(),
    getClientInfo: vi.fn(),
    listRecent: vi.fn(),
    probeDevice: vi.fn(() => Promise.resolve('offline')),
    setAccepting: vi.fn(),
  };
});

const STATUS = {
  accepting: true,
  addresses: ['192.168.1.77:7443', '[fe80::1]:7443'],
  machineName: 'PargitPC',
  listenPort: 7443,
};

const IDENTITY = {
  deviceId: 'dev-1',
  identityFingerprint: 'a'.repeat(64),
  certificateFingerprint: 'b'.repeat(64),
  certificateVersion: 1,
  certificateNotBeforeMs: 1,
  certificateNotAfterMs: 2,
  needsRenewal: false,
};

function renderPage(overrides: { readonly connection?: ConnectionState } = {}): void {
  render(
    <RemoteControlPage
      connection={overrides.connection ?? { state: 'offline' }}
      onConnection={vi.fn()}
      onConnected={vi.fn()}
      onToast={vi.fn()}
      onViewAllDevices={vi.fn()}
    />,
  );
}

describe('RemoteControlPage', () => {
  beforeEach(() => {
    vi.mocked(api.getHostStatus).mockResolvedValue(STATUS);
    vi.mocked(api.getLocalIdentity).mockResolvedValue(IDENTITY);
    vi.mocked(api.getClientInfo).mockResolvedValue({
      appVersion: '0.2.0',
      protocolVersion: { major: 1, minor: 0 },
      hostname: 'PargitPC',
      osFamily: 'windows',
      osVersion: '10.0',
      architecture: 'x64',
      elevated: false,
      databaseReady: true,
    });
    vi.mocked(api.listRecent).mockResolvedValue([]);
    vi.mocked(api.probeDevice).mockResolvedValue('offline');
    vi.mocked(api.connectToAddress).mockReset();
    vi.mocked(api.connectToAddress).mockResolvedValue({ state: 'connecting', address: 'x' });
  });

  it('makes connecting the primary action and does not colour it as a warning', () => {
    renderPage();
    const connect = screen.getByRole('button', { name: 'Connect' });
    expect(connect.className).toContain('--color-accent');
    expect(connect.className).not.toContain('--color-danger');
  });

  it('connects to the address that was typed', async () => {
    const connectToAddress = vi.mocked(api.connectToAddress);
    renderPage();

    await userEvent.type(
      screen.getByLabelText('Device ID, hostname, or IP address'),
      '192.168.1.77',
    );
    await userEvent.click(screen.getByRole('button', { name: 'Connect' }));

    expect(connectToAddress).toHaveBeenCalledWith('192.168.1.77:7443', null);
  });

  it('does not treat a device id as an address', async () => {
    renderPage();

    await userEvent.type(
      screen.getByLabelText('Device ID, hostname, or IP address'),
      '842 391 552',
    );
    await userEvent.click(screen.getByRole('button', { name: 'Connect' }));

    expect(vi.mocked(api.connectToAddress)).not.toHaveBeenCalled();
    expect(screen.getByText(/no directory/i)).toBeInTheDocument();
  });

  it('shows progress while the connection is being made rather than appearing inert', () => {
    renderPage({ connection: { state: 'connecting', address: '192.168.1.77:7443' } });

    expect(screen.getByRole('status')).toHaveTextContent(
      'Finding the device at 192.168.1.77:7443…',
    );
    expect(screen.getByRole('button', { name: 'Connect' })).toBeDisabled();
  });

  it('reports a refusal in a way that says what to do about it', () => {
    renderPage({
      connection: {
        state: 'refused',
        reason: 'identity_changed',
        message: 'That machine is not the one you trusted.',
      },
    });

    expect(screen.getByRole('alert')).toHaveTextContent('That machine is not the one you trusted.');
  });

  it('shows at most five recent devices and a way to see the rest', async () => {
    vi.mocked(api.listRecent).mockResolvedValue(
      Array.from({ length: 9 }, (_, index) => ({
        address: `10.0.0.${String(index)}:7443`,
        machineName: `Device ${String(index)}`,
        lastConnectedMs: 1_700_000_000_000 - index,
        knownIdentity: null,
      })),
    );
    renderPage();

    expect(await screen.findAllByTestId('recent-device')).toHaveLength(5);
    expect(screen.getByRole('button', { name: 'View all devices' })).toBeInTheDocument();
  });

  it('shows a recent device as offline rather than inventing a green dot', async () => {
    vi.mocked(api.listRecent).mockResolvedValue([
      {
        address: '10.0.0.1:7443',
        machineName: 'Office PC',
        lastConnectedMs: 1_700_000_000_000,
        knownIdentity: null,
      },
    ]);
    vi.mocked(api.probeDevice).mockResolvedValue('offline');
    renderPage();

    expect(await screen.findByText('Offline')).toBeInTheDocument();
  });

  it('offers a compact empty state rather than a large empty container', async () => {
    vi.mocked(api.listRecent).mockResolvedValue([]);
    renderPage();

    expect(await screen.findByText(/no recent devices/i)).toBeInTheDocument();
    expect(screen.queryByTestId('recent-device')).not.toBeInTheDocument();
  });
});
