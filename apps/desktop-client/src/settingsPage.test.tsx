import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import * as api from './api.js';
import { SettingsPage } from './SettingsPage';

vi.mock('./UpdatesPane', () => ({
  default: () => <div>Updates</div>,
}));

vi.mock('./api.js', async (importOriginal) => {
  const actual: typeof api = await importOriginal();
  return {
    ...actual,
    getHostSettings: vi.fn(),
    getHostStatus: vi.fn(),
    setUnattendedPassword: vi.fn(() => Promise.resolve(null)),
    setAccepting: vi.fn(),
    probeDevice: vi.fn(),
  };
});

describe('SettingsPage', () => {
  beforeEach(() => {
    vi.mocked(api.getHostSettings).mockResolvedValue({
      accepting: true,
      listenPort: 7443,
      machineName: 'KOREN-PC',
      unattendedConfigured: false,
      unattendedPermissions: [],
    });
    vi.mocked(api.getHostStatus).mockResolvedValue({
      accepting: true,
      addresses: ['192.168.1.77:7443'],
      machineName: 'KOREN-PC',
      listenPort: 7443,
    });
    vi.mocked(api.setUnattendedPassword).mockClear();
  });

  it('organises settings into sections rather than more navigation', async () => {
    render(<SettingsPage onToast={vi.fn()} onViewDevices={vi.fn()} />);

    for (const section of ['Remote Access', 'Security', 'Network', 'Appearance']) {
      expect(await screen.findByRole('heading', { name: section })).toBeInTheDocument();
    }
  });

  it('offers no setting this build cannot honour', async () => {
    render(<SettingsPage onToast={vi.fn()} onViewDevices={vi.fn()} />);
    await screen.findByRole('heading', { name: 'Remote Access' });

    for (const absent of [/start with system/i, /start minimi[sz]ed/i, /minimi[sz]e to tray/i]) {
      expect(screen.queryByText(absent)).not.toBeInTheDocument();
    }
  });

  it('changes the theme for real', async () => {
    render(<SettingsPage onToast={vi.fn()} onViewDevices={vi.fn()} />);

    await userEvent.click(await screen.findByRole('radio', { name: 'Dark' }));

    expect(document.documentElement.dataset['theme']).toBe('dark');
  });

  it('sets the unattended password through the backend and never renders it back', async () => {
    const setUnattendedPassword = vi.mocked(api.setUnattendedPassword);
    render(<SettingsPage onToast={vi.fn()} onViewDevices={vi.fn()} />);

    await userEvent.type(await screen.findByLabelText('Unattended password'), 'correct horse');
    await userEvent.click(screen.getByRole('button', { name: 'Save password' }));

    expect(setUnattendedPassword).toHaveBeenCalledWith('correct horse', expect.any(Array));
    expect(screen.queryByDisplayValue('correct horse')).not.toBeInTheDocument();
  });

  it('sends you to My Devices rather than duplicating the list', async () => {
    const onViewDevices = vi.fn();
    render(<SettingsPage onToast={vi.fn()} onViewDevices={onViewDevices} />);

    await userEvent.click(await screen.findByRole('button', { name: 'Manage trusted devices' }));

    expect(onViewDevices).toHaveBeenCalled();
  });
});
