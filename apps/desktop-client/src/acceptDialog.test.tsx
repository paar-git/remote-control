import { invoke } from '@tauri-apps/api/core';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { AcceptDialog } from './AcceptDialog';

const invoked = vi.mocked(invoke);

const REQUEST = {
  requestId: 'r1',
  address: '192.168.1.77:7443',
  fingerprint: 'ab'.repeat(32),
  machineName: 'WORK-LAPTOP',
};

/** Answer `pending_accept_request` with `request`, and accept any answer. */
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

/** The permissions passed to the last `answer_accept_request` call. */
function granted(): string[] | undefined {
  const call = invoked.mock.calls.findLast(([command]) => command === 'answer_accept_request');
  return (call?.[1] as { granted: string[] } | undefined)?.granted;
}

/** Whether the request was refused through the dedicated dismissal command. */
function dismissed(): boolean {
  return invoked.mock.calls.some(([command]) => command === 'dismiss_accept_request');
}

async function openDialog() {
  render(<AcceptDialog onToast={vi.fn()} />);
  return screen.findByRole('alertdialog');
}

describe('AcceptDialog', () => {
  beforeEach(() => {
    invoked.mockReset();
  });

  it('renders nothing at all when no request is waiting', async () => {
    backend(null);
    render(<AcceptDialog onToast={vi.fn()} />);

    await waitFor(() => {
      expect(invoked).toHaveBeenCalledWith('pending_accept_request', undefined);
    });
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
  });

  it('names the address, the machine and the fingerprint', async () => {
    backend();
    await openDialog();

    expect(screen.getByText('WORK-LAPTOP')).toBeInTheDocument();
    expect(screen.getByText(/192\.168\.1\.77/)).toBeInTheDocument();
    // Grouped and uppercased for reading aloud, but every one of the 64 characters is
    // present: this is the value someone compares against another screen.
    const fingerprint = screen.getByTestId('accept-fingerprint').textContent ?? '';
    expect(fingerprint.replaceAll(/\s/g, '').toLowerCase()).toBe(REQUEST.fingerprint);
  });

  it('ticks all three permissions by default', async () => {
    backend();
    await openDialog();

    for (const box of screen.getAllByRole('checkbox')) {
      expect(box).toBeChecked();
    }
    expect(screen.getAllByRole('checkbox')).toHaveLength(3);
  });

  it('gives initial focus to Dismiss, so a stray Enter refuses', async () => {
    // The whole point of the dialog. If Accept took focus, holding Enter on a keyboard
    // would hand control of the machine to whoever was knocking.
    backend();
    await openDialog();

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /dismiss/i })).toHaveFocus();
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

  it('refuses when Dismiss is clicked', async () => {
    backend();
    const user = userEvent.setup();
    await openDialog();

    await user.click(screen.getByRole('button', { name: /dismiss/i }));

    await waitFor(() => {
      expect(dismissed()).toBe(true);
    });
    expect(granted()).toBeUndefined();
  });

  it('grants all three when Accept is clicked with all three ticked', async () => {
    backend();
    const user = userEvent.setup();
    await openDialog();

    await user.click(screen.getByRole('button', { name: /^accept$/i }));

    await waitFor(() => {
      expect(granted()).toEqual(
        expect.arrayContaining(['control_input', 'transfer_files', 'view_metrics']),
      );
    });
    expect(granted()).toHaveLength(3);
  });

  it('grants only what is ticked', async () => {
    // The direction that matters: a permission the human took away must not be sent.
    backend();
    const user = userEvent.setup();
    await openDialog();

    await user.click(screen.getByRole('checkbox', { name: /transfer files/i }));
    await user.click(screen.getByRole('button', { name: /^accept$/i }));

    await waitFor(() => {
      expect(granted()).toEqual(expect.arrayContaining(['control_input', 'view_metrics']));
    });
    expect(granted()).toHaveLength(2);
    expect(granted()).not.toContain('transfer_files');
  });

  it('refuses through the dismissal command when nothing is ticked', async () => {
    // An empty grant is a refusal. The backend decides that in one place, so the
    // interface says "no" plainly rather than sending an accept of nothing.
    backend();
    const user = userEvent.setup();
    await openDialog();

    for (const box of screen.getAllByRole('checkbox')) {
      await user.click(box);
    }
    await user.click(screen.getByRole('button', { name: /^accept$/i }));

    await waitFor(() => {
      expect(dismissed()).toBe(true);
    });
    expect(granted()).toBeUndefined();
  });

  it('renders an untrusted machine name as inert text', async () => {
    // The name is chosen by whoever is knocking. It must never become markup.
    backend({ ...REQUEST, machineName: '<img src=x onerror=alert(1)>' });
    const dialog = await openDialog();

    expect(dialog.querySelector('img')).toBeNull();
    expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeInTheDocument();
  });

  it('closes once answered, so one request cannot be answered twice', async () => {
    backend();
    const user = userEvent.setup();
    await openDialog();

    await user.click(screen.getByRole('button', { name: /^accept$/i }));

    await waitFor(() => {
      expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
    });
  });
});
