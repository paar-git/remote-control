import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import * as api from './api.js';
import type { InboundSession, SessionRecord } from './api.js';
import { InboundSessionBanner } from './InboundSessionBanner';
import { SessionsPage } from './SessionsPage';

vi.mock('./api.js', async (importOriginal) => {
  const actual: typeof api = await importOriginal();
  return {
    ...actual,
    listInboundSessions: vi.fn(),
    listSessionHistory: vi.fn(),
    disconnectInbound: vi.fn(() => Promise.resolve(true)),
    emergencyDisconnect: vi.fn(),
  };
});

function inboundSession(overrides: Partial<InboundSession> = {}): InboundSession {
  return {
    sessionId: 'ses-1',
    identityFingerprint: 'a'.repeat(64),
    deviceName: 'Gaming PC',
    address: '10.0.0.1:7443',
    permissions: ['view_metrics'],
    startedMs: Date.now() - 5_000,
    ...overrides,
  };
}

function record(overrides: Partial<SessionRecord> = {}): SessionRecord {
  return {
    id: 1,
    sessionId: 'ses-9',
    identityFingerprint: 'b'.repeat(64),
    deviceName: 'Laptop',
    direction: 'incoming',
    address: '10.0.0.2:7443',
    startedMs: 1_700_000_000_000,
    endedMs: 1_700_000_060_000,
    permissions: ['view_metrics'],
    outcome: 'completed',
    endReason: null,
    ...overrides,
  };
}

function mockInbound(sessions: InboundSession[]): void {
  vi.mocked(api.listInboundSessions).mockResolvedValue(sessions);
}

function mockHistory(records: SessionRecord[]): void {
  vi.mocked(api.listSessionHistory).mockResolvedValue(records);
}

describe('SessionsPage', () => {
  beforeEach(() => {
    vi.mocked(api.listInboundSessions).mockReset();
    vi.mocked(api.listSessionHistory).mockReset();
    vi.mocked(api.disconnectInbound).mockClear();
  });

  it('separates what is happening now from what already happened', async () => {
    mockInbound([inboundSession({ deviceName: 'Gaming PC' })]);
    mockHistory([record({ deviceName: 'Laptop', outcome: 'completed' })]);
    render(<SessionsPage onToast={vi.fn()} />);

    expect(await screen.findByRole('heading', { name: 'Active Sessions' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Recent Sessions' })).toBeInTheDocument();
    expect(
      within(screen.getByTestId('active-sessions')).getByText('Gaming PC'),
    ).toBeInTheDocument();
    expect(within(screen.getByTestId('recent-sessions')).getByText('Laptop')).toBeInTheDocument();
  });

  it('shows what an active session is permitted to do', async () => {
    mockInbound([inboundSession({ permissions: ['view_metrics', 'transfer_files'] })]);
    mockHistory([]);
    render(<SessionsPage onToast={vi.fn()} />);

    expect(await screen.findByText('System Metrics')).toBeInTheDocument();
    expect(screen.getByText('File Transfer')).toBeInTheDocument();
  });

  it('disconnects an active session', async () => {
    const disconnectInbound = vi.mocked(api.disconnectInbound);
    mockInbound([inboundSession({ sessionId: 'ses-1' })]);
    mockHistory([]);
    render(<SessionsPage onToast={vi.fn()} />);

    await userEvent.click(await screen.findByRole('button', { name: 'Disconnect' }));

    expect(disconnectInbound).toHaveBeenCalledWith('ses-1');
  });

  it('shows a failed connection as failed rather than omitting it', async () => {
    mockInbound([]);
    mockHistory([record({ deviceName: 'Office PC', outcome: 'refused', endReason: null })]);
    render(<SessionsPage onToast={vi.fn()} />);

    expect(await screen.findByText('Refused')).toBeInTheDocument();
  });

  it('uses a compact empty state rather than a large empty container', async () => {
    mockInbound([]);
    mockHistory([]);
    render(<SessionsPage onToast={vi.fn()} />);

    expect(await screen.findByText(/no sessions yet/i)).toBeInTheDocument();
    expect(screen.queryByTestId('recent-sessions')).not.toBeInTheDocument();
  });
});

describe('InboundSessionBanner', () => {
  it('is absent when nobody is connected', () => {
    render(<InboundSessionBanner sessions={[]} onDisconnect={vi.fn()} onEmergency={vi.fn()} />);
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
  });

  it('says who is controlling this machine and for how long', () => {
    render(
      <InboundSessionBanner
        sessions={[inboundSession({ deviceName: 'Gaming PC', startedMs: Date.now() - 65_000 })]}
        onDisconnect={vi.fn()}
        onEmergency={vi.fn()}
      />,
    );

    const banner = screen.getByRole('status');
    expect(banner).toHaveTextContent('Gaming PC');
    expect(banner).toHaveTextContent('1m');
  });

  it('offers an emergency disconnect that is coloured as destructive', async () => {
    const onEmergency = vi.fn();
    render(
      <InboundSessionBanner
        sessions={[inboundSession({})]}
        onDisconnect={vi.fn()}
        onEmergency={onEmergency}
      />,
    );

    const button = screen.getByRole('button', { name: 'Emergency Disconnect' });
    expect(button.className).toContain('--color-danger');
    await userEvent.click(button);
    expect(onEmergency).toHaveBeenCalled();
  });
});
