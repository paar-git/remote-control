import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import * as api from './api.js';
import { RemoteControlPage } from './RemoteControlPage';

vi.mock('./api.js', async (importOriginal) => {
  const actual: typeof api = await importOriginal();
  return {
    ...actual,
    getHostStatus: vi.fn(),
    getLocalIdentity: vi.fn(),
    getClientInfo: vi.fn(),
    listRecent: vi.fn(),
    listSessionHistory: vi.fn(),
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

function renderPage(): void {
  render(
    <RemoteControlPage
      onConnect={vi.fn()}
      connectBusy={false}
      onToast={vi.fn()}
      onViewAllDevices={vi.fn()}
      onViewSessions={vi.fn()}
      onOpenSettings={vi.fn()}
      onInvite={vi.fn()}
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
    vi.mocked(api.listSessionHistory).mockResolvedValue([]);
    vi.mocked(api.probeDevice).mockResolvedValue('offline');
  });

  it('shows at most two recent devices and a way to see the rest', async () => {
    vi.mocked(api.listRecent).mockResolvedValue(
      Array.from({ length: 9 }, (_, index) => ({
        address: `10.0.0.${String(index)}:7443`,
        machineName: `Device ${String(index)}`,
        lastConnectedMs: 1_700_000_000_000 - index,
        knownIdentity: null,
      })),
    );
    renderPage();

    expect(await screen.findAllByTestId('recent-device')).toHaveLength(2);
    expect(screen.getByRole('button', { name: 'See all' })).toBeInTheDocument();
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
