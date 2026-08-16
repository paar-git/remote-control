import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { SessionToolbar, TOOLBAR_HIDE_MS, TOOLBAR_REVEAL_PX } from './SessionToolbar';

/** Every permission a session can hold, so `ALL` means what its name says. */
const ALL = [
  'view_screen',
  'control_input',
  'transfer_files',
  'view_metrics',
  'clipboard',
] as const;

function renderToolbar(permissions: readonly string[] = ALL) {
  const onDisconnect = vi.fn();
  const onOpenFiles = vi.fn();
  const onOpenMonitoring = vi.fn();
  const onToggleFitted = vi.fn();
  const onTogglePassthrough = vi.fn();
  const onRefreshScreen = vi.fn();
  render(
    <SessionToolbar
      permissions={permissions}
      machineName="WORK-LAPTOP"
      fitted
      onToggleFitted={onToggleFitted}
      passthrough={false}
      onTogglePassthrough={onTogglePassthrough}
      hasDisplayPicker={false}
      displaysOpen={false}
      onToggleDisplays={vi.fn()}
      onRefreshScreen={onRefreshScreen}
      onDisconnect={onDisconnect}
      onOpenFiles={onOpenFiles}
      onOpenMonitoring={onOpenMonitoring}
    />,
  );
  return {
    onDisconnect,
    onOpenFiles,
    onOpenMonitoring,
    onToggleFitted,
    onTogglePassthrough,
    onRefreshScreen,
  };
}

/** Move the pointer to `clientY`, as the window listener sees it. */
function movePointerTo(clientY: number) {
  act(() => {
    window.dispatchEvent(new MouseEvent('mousemove', { clientY }));
  });
}

describe('SessionToolbar', () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('offers every tool when the session holds every permission', () => {
    renderToolbar(ALL);

    for (const name of [/files/i, /monitoring/i, /fit to window/i, /keyboard/i, /full screen/i]) {
      expect(screen.getByRole('button', { name })).toBeInTheDocument();
    }
    expect(screen.getByRole('button', { name: /disconnect/i })).toBeInTheDocument();
  });

  it('omits Files entirely when the session may not transfer files', () => {
    // Absent, not disabled. A disabled button says "you could do this" and invites the
    // user to go looking for the setting that would enable it; there is no such
    // setting, because the other machine decided.
    renderToolbar(['control_input', 'view_metrics']);

    expect(screen.queryByRole('button', { name: /files/i })).not.toBeInTheDocument();
  });

  it('omits Monitoring entirely when the session may not view metrics', () => {
    renderToolbar(['control_input', 'transfer_files']);

    expect(screen.queryByRole('button', { name: /monitoring/i })).not.toBeInTheDocument();
  });

  it('keeps Disconnect regardless of permissions, because leaving is not one', () => {
    renderToolbar([]);

    expect(screen.getByRole('button', { name: /disconnect/i })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /files/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /monitoring/i })).not.toBeInTheDocument();
  });

  it('is visible on mount, so the way out is never hidden to begin with', () => {
    renderToolbar();

    expect(screen.getByRole('toolbar')).toBeVisible();
  });

  it('hides itself after a spell of no pointer movement', () => {
    renderToolbar();

    act(() => {
      vi.advanceTimersByTime(TOOLBAR_HIDE_MS + 100);
    });

    expect(screen.getByRole('toolbar')).toHaveAttribute('data-hidden', 'true');
  });

  it('stays in the accessibility tree while hidden', () => {
    // Hiding is visual only. Someone driving this with a keyboard generates no pointer
    // movement, so `aria-hidden` would take Disconnect away from them for the rest of
    // the session with no way to get it back.
    renderToolbar();
    act(() => {
      vi.advanceTimersByTime(TOOLBAR_HIDE_MS + 100);
    });

    const toolbar = screen.getByRole('toolbar');
    expect(toolbar).not.toHaveAttribute('aria-hidden');
    expect(screen.getByRole('button', { name: /disconnect/i })).toBeInTheDocument();
  });

  it('comes back when focus reaches it, not only when a pointer does', async () => {
    const user = userEvent.setup();
    renderToolbar();
    act(() => {
      vi.advanceTimersByTime(TOOLBAR_HIDE_MS + 100);
    });
    expect(screen.getByRole('toolbar')).toHaveAttribute('data-hidden', 'true');

    await user.tab();

    expect(screen.getByRole('toolbar')).not.toHaveAttribute('data-hidden');
  });

  it('comes back when the pointer nears the top edge', () => {
    renderToolbar();
    act(() => {
      vi.advanceTimersByTime(TOOLBAR_HIDE_MS + 100);
    });
    expect(screen.getByRole('toolbar')).toHaveAttribute('data-hidden', 'true');

    movePointerTo(TOOLBAR_REVEAL_PX - 10);

    expect(screen.getByRole('toolbar')).not.toHaveAttribute('data-hidden');
  });

  it('stays hidden when the pointer moves far from the top edge', () => {
    // Otherwise any movement anywhere would bring it back, and it would never be out of
    // the way of the thing it is floating over.
    renderToolbar();
    act(() => {
      vi.advanceTimersByTime(TOOLBAR_HIDE_MS + 100);
    });

    movePointerTo(TOOLBAR_REVEAL_PX + 200);

    expect(screen.getByRole('toolbar')).toHaveAttribute('data-hidden', 'true');
  });

  it('calls back the tool that was pressed', async () => {
    const user = userEvent.setup();
    const { onDisconnect, onOpenFiles, onOpenMonitoring, onToggleFitted } = renderToolbar();

    await user.click(screen.getByRole('button', { name: /files/i }));
    await user.click(screen.getByRole('button', { name: /monitoring/i }));
    await user.click(screen.getByRole('button', { name: /fit to window/i }));
    await user.click(screen.getByRole('button', { name: /disconnect/i }));

    expect(onOpenFiles).toHaveBeenCalledOnce();
    expect(onOpenMonitoring).toHaveBeenCalledOnce();
    expect(onToggleFitted).toHaveBeenCalledOnce();
    expect(onDisconnect).toHaveBeenCalledOnce();
  });

  it('reflects the fitted prop it is given rather than tracking its own', () => {
    // This is a controlled toggle now on purpose (see SessionToolbar's doc comment):
    // the button's pressed state must follow the prop, not a `useState` of its own,
    // which is exactly what let the original toggle look healthy while doing nothing.
    const { rerender } = render(
      <SessionToolbar
        permissions={ALL}
        machineName="WORK-LAPTOP"
        fitted={false}
        onToggleFitted={vi.fn()}
        passthrough={false}
        onTogglePassthrough={vi.fn()}
        hasDisplayPicker={false}
        displaysOpen={false}
        onToggleDisplays={vi.fn()}
        onRefreshScreen={vi.fn()}
        onDisconnect={vi.fn()}
        onOpenFiles={vi.fn()}
        onOpenMonitoring={vi.fn()}
      />,
    );
    expect(screen.getByRole('button', { name: /fit to window/i })).toHaveAttribute(
      'aria-pressed',
      'false',
    );

    rerender(
      <SessionToolbar
        permissions={ALL}
        machineName="WORK-LAPTOP"
        fitted
        onToggleFitted={vi.fn()}
        passthrough={false}
        onTogglePassthrough={vi.fn()}
        hasDisplayPicker={false}
        displaysOpen={false}
        onToggleDisplays={vi.fn()}
        onRefreshScreen={vi.fn()}
        onDisconnect={vi.fn()}
        onOpenFiles={vi.fn()}
        onOpenMonitoring={vi.fn()}
      />,
    );
    expect(screen.getByRole('button', { name: /fit to window/i })).toHaveAttribute(
      'aria-pressed',
      'true',
    );
  });

  it('renders an untrusted machine name as inert text', () => {
    render(
      <SessionToolbar
        permissions={ALL}
        machineName="<img src=x onerror=alert(1)>"
        fitted
        onToggleFitted={vi.fn()}
        passthrough={false}
        onTogglePassthrough={vi.fn()}
        hasDisplayPicker={false}
        displaysOpen={false}
        onToggleDisplays={vi.fn()}
        onRefreshScreen={vi.fn()}
        onDisconnect={vi.fn()}
        onOpenFiles={vi.fn()}
        onOpenMonitoring={vi.fn()}
      />,
    );

    expect(screen.getByRole('toolbar').querySelector('img')).toBeNull();
    expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeInTheDocument();
  });
});

describe('SessionToolbar keyboard passthrough', () => {
  it('asks its caller to toggle passthrough rather than deciding alone', async () => {
    // This button shipped dead once, holding its own useState and reaching nothing.
    // Asserting aria-pressed would not have caught that; asserting the callback does.
    const { onTogglePassthrough } = renderToolbar();

    await userEvent.click(screen.getByRole('button', { name: /keyboard passthrough/i }));

    expect(onTogglePassthrough).toHaveBeenCalledOnce();
  });

  it('shows the state its caller gave it, not one it invented', () => {
    render(
      <SessionToolbar
        permissions={ALL}
        machineName="WORK-LAPTOP"
        fitted
        onToggleFitted={vi.fn()}
        passthrough
        onTogglePassthrough={vi.fn()}
        hasDisplayPicker={false}
        displaysOpen={false}
        onToggleDisplays={vi.fn()}
        onRefreshScreen={vi.fn()}
        onDisconnect={vi.fn()}
        onOpenFiles={vi.fn()}
        onOpenMonitoring={vi.fn()}
      />,
    );

    expect(screen.getByRole('button', { name: /keyboard passthrough/i })).toHaveAttribute(
      'aria-pressed',
      'true',
    );
  });
});

describe('SessionToolbar refresh screen', () => {
  it('asks its caller to refresh rather than reaching the stream itself', async () => {
    const { onRefreshScreen } = renderToolbar();

    await userEvent.click(screen.getByRole('button', { name: /refresh screen/i }));

    expect(onRefreshScreen).toHaveBeenCalledOnce();
  });

  it('omits it entirely when the session may not watch the screen', () => {
    // Absent, not disabled: there is nothing to refresh, and a greyed-out button would
    // send the user looking for a setting that does not exist.
    renderToolbar(['transfer_files']);

    expect(screen.queryByRole('button', { name: /refresh screen/i })).not.toBeInTheDocument();
  });
});
