import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import * as api from './api.js';
import type { Permission, TrustedDevice } from './api.js';
import { DeviceDetail } from './DeviceDetail';

vi.mock('./api.js', async (importOriginal) => {
  const actual: typeof api = await importOriginal();
  return {
    ...actual,
    setDevicePermissions: vi.fn(() => Promise.resolve(null)),
    setDeviceUnattended: vi.fn(() => Promise.resolve(null)),
    setDeviceSuspended: vi.fn(() => Promise.resolve(null)),
    revokeDevice: vi.fn(() => Promise.resolve(null)),
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

function renderDetail(overrides: { readonly permissions?: Permission[] } = {}): void {
  render(
    <DeviceDetail
      device={device(
        overrides.permissions === undefined ? {} : { permissions: overrides.permissions },
      )}
      presence="online"
      onChanged={vi.fn()}
      onClose={vi.fn()}
      onToast={vi.fn()}
    />,
  );
}

describe('DeviceDetail', () => {
  beforeEach(() => {
    vi.mocked(api.setDevicePermissions).mockClear();
    vi.mocked(api.setDeviceUnattended).mockClear();
    vi.mocked(api.setDeviceSuspended).mockClear();
    vi.mocked(api.revokeDevice).mockClear();
  });

  it('shows access and permissions as separate sections', () => {
    renderDetail();
    expect(screen.getByRole('heading', { name: 'Access' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Permissions' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Security' })).toBeInTheDocument();
    expect(screen.getByText('Trusted device')).toBeInTheDocument();
    expect(screen.getByText('Enabled')).toBeInTheDocument();
    expect(screen.getByText('Device identity verified')).toBeInTheDocument();
  });

  it('offers only the permissions this build actually enforces', () => {
    renderDetail();
    const permissions = within(screen.getByTestId('permissions-section')).getAllByRole('switch');
    expect(permissions.map((item) => item.getAttribute('aria-label'))).toEqual([
      'Keyboard & Mouse',
      'File Transfer',
      'System Metrics',
    ]);
  });

  it('turns unattended access on without touching a permission', async () => {
    const setDeviceUnattended = vi.mocked(api.setDeviceUnattended);
    const setDevicePermissions = vi.mocked(api.setDevicePermissions);
    renderDetail();

    await userEvent.click(screen.getByRole('switch', { name: 'Connect without approval' }));

    expect(setDeviceUnattended).toHaveBeenCalledWith(IDENTITY, true);
    expect(setDevicePermissions).not.toHaveBeenCalled();
  });

  it('never grants administrator without an explicit confirmation', async () => {
    const setDevicePermissions = vi.mocked(api.setDevicePermissions);
    renderDetail();

    await userEvent.click(screen.getByRole('switch', { name: 'Administrator Access' }));

    expect(setDevicePermissions).not.toHaveBeenCalled();
    expect(screen.getByRole('dialog', { name: 'Grant Administrator Access?' })).toBeInTheDocument();
  });

  it('grants administrator only after the confirmation is accepted', async () => {
    const setDevicePermissions = vi.mocked(api.setDevicePermissions);
    renderDetail();
    await userEvent.click(screen.getByRole('switch', { name: 'Administrator Access' }));

    await userEvent.click(screen.getByRole('button', { name: 'Grant Administrator Access' }));

    expect(setDevicePermissions).toHaveBeenCalledWith(
      IDENTITY,
      expect.arrayContaining(['administer']),
    );
  });

  it('leaves administrator alone when the confirmation is cancelled', async () => {
    const setDevicePermissions = vi.mocked(api.setDevicePermissions);
    renderDetail();
    await userEvent.click(screen.getByRole('switch', { name: 'Administrator Access' }));

    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(setDevicePermissions).not.toHaveBeenCalled();
    expect(screen.getByRole('switch', { name: 'Administrator Access' })).not.toBeChecked();
  });

  it('removes administrator without a confirmation, because narrowing is always safe', async () => {
    const setDevicePermissions = vi.mocked(api.setDevicePermissions);
    renderDetail({ permissions: ['view_metrics', 'administer'] });

    await userEvent.click(screen.getByRole('switch', { name: 'Administrator Access' }));

    expect(setDevicePermissions).toHaveBeenCalledWith(IDENTITY, ['view_metrics']);
  });

  it('explains what administrator granted when the indicator is used', async () => {
    renderDetail({ permissions: ['administer'] });

    await userEvent.click(screen.getByRole('button', { name: 'Admin access' }));

    expect(screen.getByText(/manage this machine.s trusted devices/i)).toBeInTheDocument();
  });

  it('revokes with a confirmation and colours it as destructive', async () => {
    const revokeDevice = vi.mocked(api.revokeDevice);
    renderDetail();

    const revoke = screen.getByRole('button', { name: 'Revoke Access' });
    expect(revoke.className).toContain('--color-danger');
    await userEvent.click(revoke);
    await userEvent.click(screen.getByRole('button', { name: 'Revoke' }));

    expect(revokeDevice).toHaveBeenCalledWith(IDENTITY);
  });

  it('can suspend a device without revoking it', async () => {
    const setDeviceSuspended = vi.mocked(api.setDeviceSuspended);
    renderDetail();

    await userEvent.click(screen.getByRole('switch', { name: 'Temporarily disable' }));

    expect(setDeviceSuspended).toHaveBeenCalledWith(IDENTITY, true);
    expect(vi.mocked(api.revokeDevice)).not.toHaveBeenCalled();
  });
});
