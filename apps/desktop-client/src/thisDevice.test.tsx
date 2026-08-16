import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import type { HostStatus, LocalIdentity } from './api.js';
import { ThisDevice } from './ThisDevice';

const STATUS: HostStatus = {
  accepting: true,
  addresses: ['192.168.1.77:7443', '[fe80::1]:7443'],
  machineName: 'PargitPC',
  listenPort: 7443,
};

const IDENTITY: LocalIdentity = {
  deviceId: 'dev-1',
  identityFingerprint: 'a'.repeat(64),
  certificateFingerprint: 'b'.repeat(64),
  certificateVersion: 1,
  certificateNotBeforeMs: 1,
  certificateNotAfterMs: 2,
  needsRenewal: false,
};

function renderThisDevice(
  overrides: {
    readonly status?: Partial<HostStatus>;
    readonly onToggleAccepting?: (next: boolean) => void;
  } = {},
): void {
  render(
    <ThisDevice
      status={{ ...STATUS, ...overrides.status }}
      identity={IDENTITY}
      os="windows"
      hostname="PargitPC"
      onToggleAccepting={overrides.onToggleAccepting ?? vi.fn()}
    />,
  );
}

describe('ThisDevice', () => {
  it('shows a grouped device id with copy and share', () => {
    renderThisDevice();
    const id = screen.getByLabelText('Device ID');
    expect(id.textContent).toMatch(/^\d{3} \d{3} \d{3}$/);
    expect(screen.getAllByRole('button', { name: 'Copy' }).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByTitle('Copy device ID')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Share' })).toBeInTheDocument();
    expect(screen.getByText(/verify this on the other machine/i)).toBeInTheDocument();
  });

  it('still shows the address, because that is what the other machine dials', () => {
    renderThisDevice();
    expect(screen.getByLabelText('Connect using')).toHaveTextContent('192.168.1.77:7443');
  });

  it('keeps IPv6 and hostname out of the way until they are asked for', async () => {
    renderThisDevice();
    expect(screen.queryByText('fe80::1')).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: /advanced network information/i }));

    expect(screen.getByText('fe80::1')).toBeInTheDocument();
    expect(screen.getByText('Direct QUIC / TLS 1.3')).toBeInTheDocument();
    expect(screen.getByText('Not used — this build connects directly')).toBeInTheDocument();
  });

  it('turns incoming connections on and off for real', async () => {
    const onToggleAccepting = vi.fn();
    renderThisDevice({ onToggleAccepting });

    await userEvent.click(screen.getByRole('switch', { name: 'Allow incoming connections' }));

    expect(onToggleAccepting).toHaveBeenCalledWith(false);
  });

  it('says it is not reachable when incoming connections are off', () => {
    renderThisDevice({ status: { accepting: false } });
    expect(screen.getByRole('status')).toHaveTextContent('Not accepting connections');
  });
});
