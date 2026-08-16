import { invoke } from '@tauri-apps/api/core';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import * as api from './api.js';
import { AcceptDialog } from './AcceptDialog';

const invoked = vi.mocked(invoke);

const REQUEST = {
  requestId: 'r1',
  address: '192.168.1.77:7443',
  identityFingerprint: 'ab'.repeat(32),
  deviceId: 'dev-1',
  machineName: 'WORK-LAPTOP',
  osFamily: 'windows',
  trusted: false,
};

function backend(request: Record<string, unknown> | null = REQUEST) {
  invoked.mockImplementation((command: string) => {
    switch (command) {
      case 'pending_accept_request':
        return Promise.resolve(request);
      case 'answer_accept_request':
      case 'dismiss_accept_request':
        return Promise.resolve(null);
      default:
        return Promise.reject(new Error(`unexpected command ${command}`));
    }
  });
}

function granted(): string[] | undefined {
  const call = invoked.mock.calls.findLast(([command]) => command === 'answer_accept_request');
  return (call?.[1] as { granted: string[] } | undefined)?.granted;
}

function trust(): string | undefined {
  const call = invoked.mock.calls.findLast(([command]) => command === 'answer_accept_request');
  return (call?.[1] as { trust: string } | undefined)?.trust;
}

function dismissed(): boolean {
  return invoked.mock.calls.some(([command]) => command === 'dismiss_accept_request');
}

async function openDialog() {
  render(<AcceptDialog onToast={vi.fn()} />);
  return screen.findByRole('dialog');
}

async function raise(overrides: Record<string, unknown>): Promise<void> {
  backend({
    requestId: 'req-1',
    address: '192.168.1.77:7443',
    identityFingerprint: 'ab'.repeat(32),
    deviceId: 'dev-1',
    machineName: 'Koren Laptop',
    osFamily: 'windows',
    trusted: false,
    ...overrides,
  });
  render(<AcceptDialog onToast={vi.fn()} />);
  await screen.findByRole('dialog');
}

describe('AcceptDialog', () => {
  beforeEach(() => {
    invoked.mockReset();
    vi.restoreAllMocks();
  });

  it('renders nothing at all when no request is waiting', async () => {
    backend(null);
    render(<AcceptDialog onToast={vi.fn()} />);

    await waitFor(() => {
      expect(invoked).toHaveBeenCalledWith('pending_accept_request', undefined);
    });
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('names the address, the machine and the fingerprint', async () => {
    backend();
    await openDialog();

    expect(screen.getByText('WORK-LAPTOP')).toBeInTheDocument();
    expect(screen.getByText(/192\.168\.1\.77/)).toBeInTheDocument();
    const fingerprint = screen.getByTestId('accept-fingerprint').textContent ?? '';
    expect(fingerprint.replaceAll(/\s/g, '').toLowerCase()).toBe(REQUEST.identityFingerprint);
  });

  it('ticks every grantable permission by default', async () => {
    backend();
    await openDialog();

    for (const box of screen.getAllByRole('checkbox')) {
      expect(box).toBeChecked();
    }
    expect(screen.getAllByRole('checkbox')).toHaveLength(4);
  });

  it('gives initial focus to Reject, so a stray Enter refuses', async () => {
    backend();
    await openDialog();

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /reject/i })).toHaveFocus();
    });
  });

  it('refuses when Escape is pressed', async () => {
    backend();
    const user = userEvent.setup();
    await openDialog();

    await user.keyboard('{Escape}');

    await waitFor(() => {
      expect(dismissed()).toBe(true);
    });
    expect(granted()).toBeUndefined();
  });

  it('refuses when Reject is clicked', async () => {
    backend();
    const user = userEvent.setup();
    await openDialog();

    await user.click(screen.getByRole('button', { name: /reject/i }));

    await waitFor(() => {
      expect(dismissed()).toBe(true);
    });
    expect(granted()).toBeUndefined();
  });

  it('grants every permission when Accept Once is clicked with all of them ticked', async () => {
    backend();
    const user = userEvent.setup();
    await openDialog();

    await user.click(screen.getByRole('button', { name: 'Accept Once' }));

    await waitFor(() => {
      expect(granted()).toEqual(
        expect.arrayContaining(['view_screen', 'control_input', 'transfer_files', 'view_metrics']),
      );
    });
    expect(granted()).toHaveLength(4);
    expect(trust()).toBe('once');
  });

  it('grants only what is ticked', async () => {
    backend();
    const user = userEvent.setup();
    await openDialog();

    await user.click(screen.getByRole('checkbox', { name: /file transfer/i }));
    await user.click(screen.getByRole('button', { name: 'Accept Once' }));

    await waitFor(() => {
      expect(granted()).toEqual(
        expect.arrayContaining(['view_screen', 'control_input', 'view_metrics']),
      );
    });
    expect(granted()).toHaveLength(3);
    expect(granted()).not.toContain('transfer_files');
  });

  it('refuses through the dismissal command when nothing is ticked', async () => {
    backend();
    const user = userEvent.setup();
    await openDialog();

    for (const box of screen.getAllByRole('checkbox')) {
      await user.click(box);
    }
    await user.click(screen.getByRole('button', { name: 'Accept Once' }));

    await waitFor(() => {
      expect(dismissed()).toBe(true);
    });
    expect(granted()).toBeUndefined();
  });

  it('renders an untrusted machine name as inert text', async () => {
    backend({ ...REQUEST, machineName: '<img src=x onerror=alert(1)>' });
    const dialog = await openDialog();

    expect(dialog.querySelector('img')).toBeNull();
    expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeInTheDocument();
  });

  it('closes once answered, so one request cannot be answered twice', async () => {
    backend();
    const user = userEvent.setup();
    await openDialog();

    await user.click(screen.getByRole('button', { name: 'Accept Once' }));

    await waitFor(() => {
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });
  });

  it('identifies the device that is knocking', async () => {
    await raise({ machineName: 'Koren Laptop', deviceId: 'dev-1', osFamily: 'windows' });

    const dialog = screen.getByRole('dialog');
    expect(dialog).toHaveTextContent('Koren Laptop');
    expect(dialog).toHaveTextContent('Windows');
    expect(dialog.textContent ?? '').toMatch(/\d{3} \d{3} \d{3}/);
  });

  it('says whether this device is already trusted', async () => {
    await raise({ trusted: true });
    expect(screen.getByText('Trusted device')).toBeInTheDocument();
  });

  it('accepts once without remembering anything', async () => {
    const answer = vi.spyOn(api, 'answerAcceptRequest');
    await raise({});

    await userEvent.click(screen.getByRole('button', { name: 'Accept Once' }));

    expect(answer).toHaveBeenCalledWith('req-1', expect.any(Array), 'once');
  });

  it('remembers a device without letting it in unasked', async () => {
    const answer = vi.spyOn(api, 'answerAcceptRequest');
    await raise({});

    await userEvent.click(screen.getByRole('button', { name: 'Accept & Trust' }));
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }));

    expect(answer).toHaveBeenCalledWith('req-1', expect.any(Array), 'remember');
  });

  it('does not offer unattended access from the primary buttons', async () => {
    await raise({});

    expect(screen.queryByRole('button', { name: /allow unattended/i })).not.toBeInTheDocument();
  });

  it('grants unattended access only after the extra step is taken', async () => {
    const answer = vi.spyOn(api, 'answerAcceptRequest');
    await raise({});

    await userEvent.click(screen.getByRole('button', { name: 'Accept & Trust' }));
    await userEvent.click(screen.getByRole('checkbox', { name: /connect without approval/i }));
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }));

    expect(answer).toHaveBeenCalledWith('req-1', expect.any(Array), 'remember_unattended');
  });

  it('never offers administrator', async () => {
    await raise({});
    expect(screen.queryByText(/administrator/i)).not.toBeInTheDocument();
  });

  it('refuses when nothing is ticked rather than opening an empty session', async () => {
    const answer = vi.spyOn(api, 'answerAcceptRequest');
    const dismiss = vi.spyOn(api, 'dismissAcceptRequest');
    await raise({});
    for (const box of screen.getAllByRole('checkbox')) await userEvent.click(box);

    await userEvent.click(screen.getByRole('button', { name: 'Accept Once' }));

    expect(answer).not.toHaveBeenCalled();
    expect(dismiss).toHaveBeenCalledWith('req-1');
  });
});
