import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import { AppShell } from './AppShell';

const IDENTITY = {
  deviceId: 'dev-1',
  identityFingerprint: 'a'.repeat(64),
  certificateFingerprint: 'b'.repeat(64),
  certificateVersion: 1,
  certificateNotBeforeMs: 1,
  certificateNotAfterMs: 2,
  needsRenewal: false,
};

function renderShell(
  overrides: {
    readonly view?: 'remote-control' | 'my-devices' | 'sessions' | 'settings';
    readonly onNavigate?: (view: 'remote-control' | 'my-devices' | 'sessions' | 'settings') => void;
    readonly banner?: React.ReactNode;
  } = {},
): void {
  render(
    <AppShell
      view={overrides.view ?? 'remote-control'}
      onNavigate={overrides.onNavigate ?? vi.fn()}
      banner={overrides.banner ?? null}
      connection={{ state: 'offline' }}
      status={{
        accepting: true,
        addresses: ['192.168.1.77:7443'],
        machineName: 'PargitPC',
        listenPort: 7443,
      }}
      identity={IDENTITY}
      recent={[]}
      address=""
      onAddressChange={vi.fn()}
      onSubmit={vi.fn()}
      parseError={null}
      busy={false}
      failed={false}
      inputRef={{ current: null }}
      onPickRecent={vi.fn()}
      onConnectWithPassword={vi.fn()}
      onNewSession={vi.fn()}
      onInvite={vi.fn()}
    >
      <p>content</p>
    </AppShell>,
  );
}

describe('AppShell', () => {
  it('offers exactly the four categories', () => {
    renderShell();

    const nav = screen.getByRole('navigation', { name: 'Main' });
    const items = within(nav).getAllByRole('button');
    expect(items.map((item) => item.textContent)).toEqual([
      'Remote Control',
      'My Devices',
      'Sessions',
      'Settings',
    ]);
  });

  it('marks the current category so it is obvious which one you are on', () => {
    renderShell({ view: 'sessions' });

    expect(screen.getByRole('button', { name: 'Sessions' })).toHaveAttribute(
      'aria-current',
      'page',
    );
    expect(screen.getByRole('button', { name: 'My Devices' })).not.toHaveAttribute('aria-current');
  });

  it('navigates when a category is chosen', async () => {
    const onNavigate = vi.fn();
    renderShell({ onNavigate });

    await userEvent.click(screen.getByRole('button', { name: 'My Devices' }));

    expect(onNavigate).toHaveBeenCalledWith('my-devices');
  });

  it('has no disabled navigation item', () => {
    renderShell();

    const nav = screen.getByRole('navigation', { name: 'Main' });
    for (const item of within(nav).getAllByRole('button')) {
      expect(item).toBeEnabled();
    }
  });

  it('renders a banner above the content when one is given', () => {
    renderShell({ banner: <p>someone is connected</p> });

    expect(screen.getByText('someone is connected')).toBeInTheDocument();
  });

  it('uses horizontal navigation rather than a sidebar', () => {
    renderShell();
    expect(screen.queryByRole('complementary')).not.toBeInTheDocument();
    expect(screen.getByRole('navigation', { name: 'Main' }).className).toContain('shrink-0');
  });
});
