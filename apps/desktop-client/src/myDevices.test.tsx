import { act, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import * as api from './api.js';
import type { TrustedDevice } from './api.js';
import { MyDevicesPage } from './MyDevicesPage';

vi.mock('./api.js', async (importOriginal) => {
  const actual: typeof api = await importOriginal();
  return {
    ...actual,
    listTrustedDevices: vi.fn(),
    probeDevice: vi.fn(),
    connectToAddress: vi.fn(),
    setDevicePermissions: vi.fn(),
    setDeviceUnattended: vi.fn(),
    setDeviceSuspended: vi.fn(),
    revokeDevice: vi.fn(),
  };
});

const IDENTITY = 'a'.repeat(64);

function device(overrides: Partial<TrustedDevice> = {}): TrustedDevice {
  return {
    identityFingerprint: IDENTITY,
    deviceId: 'dev-1',
    displayName: 'Gaming PC',
    osFamily: 'windows',
    lastAddress: '192.168.1.77:7443',
    addedMs: 1_700_000_000_000,
    lastConnectedMs: 1_700_000_060_000,
    unattended: false,
    suspended: false,
    permissions: ['view_metrics'],
    ...overrides,
  };
}

function mockDevices(devices: TrustedDevice[]): void {
  vi.mocked(api.listTrustedDevices).mockResolvedValue(devices);
}

describe('MyDevicesPage', () => {
  beforeEach(() => {
    vi.mocked(api.listTrustedDevices).mockReset();
    vi.mocked(api.probeDevice).mockReset();
    vi.mocked(api.probeDevice).mockResolvedValue('offline');
  });

  it('shows a trusted device with what it may do and when it was last used', async () => {
    mockDevices([device({ displayName: 'Gaming PC', osFamily: 'windows', unattended: true })]);
    render(<MyDevicesPage onConnect={vi.fn()} onToast={vi.fn()} />);

    expect(await screen.findByText('Gaming PC')).toBeInTheDocument();
    expect(screen.getByText('Windows')).toBeInTheDocument();
    expect(screen.getByText('Unattended access')).toBeInTheDocument();
    expect(screen.getByText(/last connected/i)).toBeInTheDocument();
  });

  it('shows a device as online only once the probe has said so', async () => {
    mockDevices([device({ lastAddress: '10.0.0.1:7443' })]);
    let resolve: (value: 'online') => void = () => undefined;
    vi.mocked(api.probeDevice).mockReturnValue(
      new Promise((r) => {
        resolve = r;
      }),
    );
    render(<MyDevicesPage onConnect={vi.fn()} onToast={vi.fn()} />);

    expect(await screen.findByText('Checking…')).toBeInTheDocument();
    act(() => {
      resolve('online');
    });
    expect(await screen.findByText('Online')).toBeInTheDocument();
  });

  it('says offline rather than nothing when a device cannot be reached', async () => {
    mockDevices([device({ lastAddress: '10.0.0.1:7443' })]);
    vi.mocked(api.probeDevice).mockResolvedValue('offline');
    render(<MyDevicesPage onConnect={vi.fn()} onToast={vi.fn()} />);

    expect(await screen.findByText('Offline')).toBeInTheDocument();
  });

  it('marks an administrator without shouting about it', async () => {
    mockDevices([device({ permissions: ['view_metrics', 'administer'] })]);
    render(<MyDevicesPage onConnect={vi.fn()} onToast={vi.fn()} />);

    const badge = await screen.findByText('Admin access');
    expect(badge.className).not.toContain('--color-danger');
  });

  it('has a compact empty state when nothing has been trusted yet', async () => {
    mockDevices([]);
    render(<MyDevicesPage onConnect={vi.fn()} onToast={vi.fn()} />);

    expect(await screen.findByText(/no trusted devices yet/i)).toBeInTheDocument();
  });
});
