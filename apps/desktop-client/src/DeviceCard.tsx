/**
 * One trusted device as a dense desktop row.
 */

import { MoreHorizontal } from 'lucide-react';
import { useState } from 'react';

import type { Presence, TrustedDevice } from './api.js';
import { DeviceAvatar } from './DeviceAvatar';
import { formatDeviceId, formatRelative } from './format.js';
import { osLabel, permissionLabel } from './labels.js';
import { Button, IconButton, StatusBadge } from './ui';

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
  const [adminOpen, setAdminOpen] = useState(false);
  const os = osFamilyOf(device.osFamily);
  const canDial = device.lastAddress !== null && !device.suspended;
  const summary = device.permissions.map(permissionLabel).join(' · ');

  return (
    <article>
      <div className="flex min-h-16 items-center gap-3 px-4 py-2 transition-colors duration-125 hover:bg-(--color-hover)">
        <DeviceAvatar name={device.displayName} os={os} size="sm" />
        <div className="min-w-[160px] flex-1">
          <p className="truncate text-[15px] font-medium" title={device.displayName}>
            {device.displayName}
          </p>
          <p className="truncate text-[13px] text-(--color-text-secondary)">
            <span>{osLabel(device.osFamily)}</span>
            {' · '}
            Last connected {formatRelative(device.lastConnectedMs)}
          </p>
        </div>
        <p className="hidden font-mono text-[13px] text-(--color-text-secondary) sm:block">
          {formatDeviceId(device.identityFingerprint)}
        </p>
        <PresenceLabel presence={presence} />
        <div className="flex min-w-0 flex-1 items-center gap-2">
          <StatusBadge tone={device.unattended ? 'ready' : 'idle'} icon={false}>
            {device.unattended ? 'Unattended access' : 'Trusted access'}
          </StatusBadge>
          {device.permissions.includes('administer') && (
            <button
              type="button"
              className="rounded-[3px] bg-(--color-hover) px-2 py-0.5 text-[11px] font-medium text-(--color-text-secondary)"
              onClick={() => {
                setAdminOpen((open) => !open);
              }}
            >
              Admin access
            </button>
          )}
          {device.suspended && (
            <StatusBadge tone="warning" icon={false}>
              Suspended
            </StatusBadge>
          )}
          <span className="hidden truncate text-[12px] text-(--color-text-muted) xl:inline">
            {summary}
          </span>
        </div>
        <Button variant="primary" size="sm" disabled={busy || !canDial} onClick={onConnect}>
          Connect
        </Button>
        <IconButton icon={MoreHorizontal} label="Device details" onClick={onOpen} />
      </div>
      {adminOpen && (
        <p className="px-4 pb-2 text-xs text-(--color-text-secondary)">
          Can manage this machine’s trusted devices: list them, change what they may do, and revoke
          them.
        </p>
      )}
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
