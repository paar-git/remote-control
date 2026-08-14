import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import { AppShell } from './AppShell';

describe('AppShell', () => {
  it('offers exactly the four categories', () => {
    render(
      <AppShell view="remote-control" onNavigate={vi.fn()} banner={null}>
        <p>content</p>
      </AppShell>,
    );

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
    render(
      <AppShell view="sessions" onNavigate={vi.fn()} banner={null}>
        <p>content</p>
      </AppShell>,
    );

    expect(screen.getByRole('button', { name: 'Sessions' })).toHaveAttribute(
      'aria-current',
      'page',
    );
    expect(screen.getByRole('button', { name: 'My Devices' })).not.toHaveAttribute('aria-current');
  });

  it('navigates when a category is chosen', async () => {
    const onNavigate = vi.fn();
    render(
      <AppShell view="remote-control" onNavigate={onNavigate} banner={null}>
        <p>content</p>
      </AppShell>,
    );

    await userEvent.click(screen.getByRole('button', { name: 'My Devices' }));

    expect(onNavigate).toHaveBeenCalledWith('my-devices');
  });

  it('has no disabled navigation item', () => {
    // Every category must lead somewhere. A permanently disabled item is a
    // placeholder, which is the thing this rework removes.
    render(
      <AppShell view="remote-control" onNavigate={vi.fn()} banner={null}>
        <p>content</p>
      </AppShell>,
    );

    const nav = screen.getByRole('navigation', { name: 'Main' });
    for (const item of within(nav).getAllByRole('button')) {
      expect(item).toBeEnabled();
    }
  });

  it('renders a banner above the content when one is given', () => {
    render(
      <AppShell view="remote-control" onNavigate={vi.fn()} banner={<p>someone is connected</p>}>
        <p>content</p>
      </AppShell>,
    );

    expect(screen.getByText('someone is connected')).toBeInTheDocument();
  });
});
