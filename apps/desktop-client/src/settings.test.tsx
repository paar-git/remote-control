import { invoke } from '@tauri-apps/api/core';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { SettingsDialog } from './SettingsDialog';

const invoked = vi.mocked(invoke);

const SETTINGS = {
  accepting: true,
  listenPort: 7443,
  machineName: 'KOREN-PC',
  unattendedConfigured: false,
  unattendedPermissions: [],
};

const IDENTITY = {
  deviceId: 'dev_1',
  identityFingerprint: 'cd'.repeat(32),
  certificateFingerprint: 'ef'.repeat(32),
  certificateVersion: 1,
  certificateNotBeforeMs: 0,
  certificateNotAfterMs: 1,
  needsRenewal: false,
};

function backend(
  overrides: {
    settings?: Record<string, unknown>;
    savePassword?: () => unknown;
  } = {},
) {
  invoked.mockImplementation((command: string) => {
    switch (command) {
      case 'host_settings':
        return Promise.resolve({ ...SETTINGS, ...overrides.settings });
      case 'local_identity':
        return Promise.resolve(IDENTITY);
      case 'client_info':
        return Promise.resolve({
          appVersion: '0.1.1',
          protocolVersion: { major: 1, minor: 0 },
          hostname: 'koren-pc',
          osFamily: 'windows',
          osVersion: 'Windows 11',
          architecture: 'x86_64',
          elevated: false,
          databaseReady: true,
        });
      case 'update_status':
        return Promise.resolve({ state: 'idle', currentVersion: '0.1.1', available: null });
      case 'set_unattended_password':
        return Promise.resolve(overrides.savePassword?.() ?? null);
      case 'set_accepting':
        return Promise.resolve({
          accepting: true,
          addresses: [],
          machineName: 'KOREN-PC',
          listenPort: 7443,
        });
      default:
        return Promise.reject(new Error(`unexpected command ${command}`));
    }
  });
}

/** The arguments of the last `set_unattended_password` call, if there was one. */
function savedPassword(): { password: string | null; permissions: string[] } | undefined {
  const call = invoked.mock.calls.findLast(([command]) => command === 'set_unattended_password');
  return call?.[1] as { password: string | null; permissions: string[] } | undefined;
}

async function openSettings() {
  render(<SettingsDialog onClose={vi.fn()} onToast={vi.fn()} />);
  return screen.findByRole('dialog');
}

describe('SettingsDialog', () => {
  beforeEach(() => {
    invoked.mockReset();
  });

  it('renders its four sections', async () => {
    backend();
    await openSettings();

    for (const heading of [/this computer/i, /incoming connections/i, /updates/i, /^about$/i]) {
      expect(await screen.findByRole('heading', { name: heading })).toBeInTheDocument();
    }
  });

  it('has unattended access off, with no password field, until it is switched on', async () => {
    // Off by default is the whole point: a machine nobody configured must not be
    // reachable without someone clicking Accept.
    backend();
    await openSettings();

    const toggle = await screen.findByRole('checkbox', { name: /unattended access/i });
    expect(toggle).not.toBeChecked();
    expect(screen.queryByLabelText(/^password/i)).not.toBeInTheDocument();
  });

  it('shows the password field once unattended access is switched on', async () => {
    backend();
    const user = userEvent.setup();
    await openSettings();

    await user.click(await screen.findByRole('checkbox', { name: /unattended access/i }));

    expect(await screen.findByLabelText(/^password/i)).toBeInTheDocument();
  });

  it('refuses a password shorter than the floor without calling the backend', async () => {
    // The backend enforces this too. Refusing here means the user is told before a
    // round trip, not that the rule lives only in the interface.
    backend();
    const user = userEvent.setup();
    await openSettings();

    await user.click(await screen.findByRole('checkbox', { name: /unattended access/i }));
    await user.type(await screen.findByLabelText(/^password/i), 'short');
    await user.click(screen.getByRole('button', { name: /save password/i }));

    // The alert specifically, not the field's help text, which says the same thing
    // before anything has gone wrong.
    expect(await screen.findByTestId('unattended-error')).toHaveTextContent(/at least 12/i);
    expect(savedPassword()).toBeUndefined();
  });

  it('saves a valid password once, with the chosen permissions', async () => {
    backend();
    const user = userEvent.setup();
    await openSettings();

    await user.click(await screen.findByRole('checkbox', { name: /unattended access/i }));
    await user.type(await screen.findByLabelText(/^password/i), 'correct horse battery staple');
    // Take one away, so the assertion is about the choice and not about the default.
    await user.click(screen.getByRole('checkbox', { name: /transfer files/i }));
    await user.click(screen.getByRole('button', { name: /save password/i }));

    await waitFor(() => {
      expect(savedPassword()?.password).toBe('correct horse battery staple');
    });
    expect(savedPassword()?.permissions).toEqual(
      expect.arrayContaining(['control_input', 'view_metrics']),
    );
    expect(savedPassword()?.permissions).not.toContain('transfer_files');
    expect(
      invoked.mock.calls.filter(([command]) => command === 'set_unattended_password'),
    ).toHaveLength(1);
  });

  it('clears the password when unattended access is switched off', async () => {
    backend({ settings: { unattendedConfigured: true, unattendedPermissions: ['view_metrics'] } });
    const user = userEvent.setup();
    await openSettings();

    const toggle = await screen.findByRole('checkbox', { name: /unattended access/i });
    await waitFor(() => {
      expect(toggle).toBeChecked();
    });
    await user.click(toggle);

    await waitFor(() => {
      expect(savedPassword()?.password).toBeNull();
    });
  });

  it('never leaves the password in a DOM attribute', async () => {
    // A value attribute would put it in the accessibility tree, in a DOM snapshot and
    // in anything that serialises the document.
    backend();
    const user = userEvent.setup();
    const dialog = await openSettings();

    await user.click(await screen.findByRole('checkbox', { name: /unattended access/i }));
    const field = await screen.findByLabelText(/^password/i);
    await user.type(field, 'correct horse battery staple');
    await user.click(screen.getByRole('button', { name: /save password/i }));

    await waitFor(() => {
      expect(savedPassword()).toBeDefined();
    });
    expect(dialog.outerHTML).not.toContain('correct horse battery staple');
    expect(field).toHaveAttribute('type', 'password');
  });

  it('reverts the control and says why when a save fails', async () => {
    // Otherwise the window would show a state the machine is not in, and the user would
    // believe unattended access was on when it was not.
    backend({
      savePassword: () => {
        throw new Error('That could not be saved.');
      },
    });
    const user = userEvent.setup();
    await openSettings();

    const toggle = await screen.findByRole('checkbox', { name: /unattended access/i });
    await user.click(toggle);
    await user.type(await screen.findByLabelText(/^password/i), 'correct horse battery staple');
    await user.click(screen.getByRole('button', { name: /save password/i }));

    expect(await screen.findByTestId('unattended-error')).toHaveTextContent(/could not be saved/i);
    await waitFor(() => {
      expect(screen.getByRole('checkbox', { name: /unattended access/i })).not.toBeChecked();
    });
  });

  it('shows the version and this machine’s identity fingerprint', async () => {
    backend();
    await openSettings();

    expect(await screen.findByText(/0\.1\.1/)).toBeInTheDocument();
    const shown = (await screen.findByTestId('about-fingerprint')).textContent ?? '';
    expect(shown.replaceAll(/\s/g, '').toLowerCase()).toBe(IDENTITY.identityFingerprint);
  });
});
