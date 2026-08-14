/**
 * Persistent navigation. Home is this window; Settings opens the existing dialog;
 * session tools stay disabled until there is a live session to use them in.
 */

import { FolderOpen, Home, Monitor, Settings, Waypoints } from 'lucide-react';

import { Tooltip } from './ui/Tooltip';

export function AppSidebar({
  onOpenSettings,
  onShowDevices,
  sessionLive,
}: {
  readonly onOpenSettings: () => void;
  readonly onShowDevices: () => void;
  readonly sessionLive: boolean;
}): React.JSX.Element {
  return (
    <nav
      aria-label="Main"
      className="flex w-[72px] shrink-0 flex-col items-center gap-1 border-r border-(--color-border) bg-(--color-sidebar) py-4"
    >
      <NavItem icon={Home} label="Home" active />
      <NavItem icon={Monitor} label="Devices" onClick={onShowDevices} />
      <NavItem
        icon={Waypoints}
        label="Sessions"
        disabled={!sessionLive}
        disabledReason="Available during a session"
      />
      <NavItem
        icon={FolderOpen}
        label="File transfer"
        disabled={!sessionLive}
        disabledReason="Available during a session"
      />
      <div className="mt-auto">
        <NavItem icon={Settings} label="Settings" onClick={onOpenSettings} />
      </div>
    </nav>
  );
}

function NavItem({
  icon: Icon,
  label,
  active = false,
  disabled = false,
  disabledReason,
  onClick,
}: {
  readonly icon: typeof Home;
  readonly label: string;
  readonly active?: boolean | undefined;
  readonly disabled?: boolean | undefined;
  readonly disabledReason?: string | undefined;
  readonly onClick?: (() => void) | undefined;
}): React.JSX.Element {
  const button = (
    <button
      type="button"
      aria-label={label}
      aria-current={active ? 'page' : undefined}
      disabled={disabled}
      onClick={onClick}
      className={
        'flex size-11 items-center justify-center rounded-xl transition-colors duration-150 ease-(--ease-ui) ' +
        (active
          ? 'bg-(--color-accent-soft) text-(--color-accent)'
          : 'text-(--color-text-secondary) hover:bg-(--color-hover) hover:text-(--color-text) ') +
        'disabled:pointer-events-none disabled:opacity-35'
      }
    >
      <Icon aria-hidden="true" className="size-5" />
    </button>
  );

  return (
    <Tooltip label={disabled && disabledReason !== undefined ? disabledReason : label} side="right">
      {button}
    </Tooltip>
  );
}
