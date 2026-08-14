/**
 * One trusted device: who it is, whether it is reachable, and what it may do.
 */

import { MoreHorizontal } from 'lucide-react';

import type { Presence, TrustedDevice } from './api.js';
import { DeviceAvatar } from './DeviceAvatar';
import { formatRelative } from './format.js';
import { osLabel } from './labels.js';
import { Button, StatusBadge } from './ui';

export function DeviceCard({
  device,
  presence,
  onConnect,
  onOpen,
  busy = false,
}: {
  readonly device: TrustedDevice;
  readonly presence: Presence;
  readonly onConnect: () => void;
  readonly onOpen: () => void;
  readonly busy?: boolean | undefined;
}): React.JSX.Element {
  const os = osFamilyOf(device.osFamily);
  const canDial = device.lastAddress !== null && !device.suspended;

  return (
    <article className="flex flex-col gap-4 rounded-[var(--radius-card)] border border-(--color-border) bg-(--color-card) p-5 shadow-(--shadow-card)">
      <div className="flex items-start gap-3">
        <DeviceAvatar name={device.displayName} os={os} />
        <div className="min-w-0 flex-1">
          <div className="flex items-start justify-between gap-2">
            <p className="truncate text-base font-semibold" title={device.displayName}>
              {device.displayName}
            </p>
            <PresenceLabel presence={presence} />
          </div>
          <p className="mt-0.5 text-sm text-(--color-text-secondary)">{osLabel(device.osFamily)}</p>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <StatusBadge tone={device.unattended ? 'ready' : 'idle'} icon={false}>
          {device.unattended ? 'Unattended access' : 'Trusted access'}
        </StatusBadge>
        {device.permissions.includes('administer') && (
          <span className="rounded-full bg-(--color-hover) px-2 py-0.5 text-[11px] font-medium text-(--color-text-secondary)">
            Admin access
          </span>
        )}
        {device.suspended && (
          <StatusBadge tone="warning" icon={false}>
            Suspended
          </StatusBadge>
        )}
      </div>

      <p className="text-xs text-(--color-text-secondary)">
        Last connected {formatRelative(device.lastConnectedMs)}
      </p>

      <div className="flex items-center gap-2">
        <Button variant="primary" disabled={busy || !canDial} onClick={onConnect}>
          Connect
        </Button>
        <Button variant="ghost" icon={MoreHorizontal} onClick={onOpen} title="Device details">
          Details
        </Button>
      </div>
    </article>
  );
}

function PresenceLabel({ presence }: { readonly presence: Presence }): React.JSX.Element {
  if (presence === 'checking') {
    return <StatusBadge tone="busy">Checking…</StatusBadge>;
  }
  if (presence === 'online') {
    return <StatusBadge tone="ready">Online</StatusBadge>;
  }
  return <StatusBadge tone="idle">Offline</StatusBadge>;
}

function osFamilyOf(family: string): 'windows' | 'linux' | 'macos' | 'unknown' {
  if (family === 'windows' || family === 'linux' || family === 'macos') return family;
  return 'unknown';
}
