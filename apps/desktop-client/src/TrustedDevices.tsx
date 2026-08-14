/**
 * Machines this installation has pinned for always-allow.
 *
 * These are recent entries with a pin, not a second list. There is no live presence, so
 * a machine is described by when it was last used, not by a fabricated online state.
 */

import { Shield } from 'lucide-react';

import type { Recent } from './api.js';
import { DeviceAvatar } from './DeviceAvatar';
import { formatRelative } from './format.js';
import { Button, Card } from './ui';

export function TrustedDevices({
  entries,
  onConnect,
  busy,
}: {
  readonly entries: readonly Recent[];
  readonly onConnect: (address: string) => void;
  readonly busy: boolean;
}): React.JSX.Element {
  const trusted = entries.filter((entry) => entry.alwaysAllow);

  return (
    <Card>
      <h2 className="mb-5 text-xl font-semibold tracking-tight">Trusted devices</h2>

      {trusted.length === 0 ? (
        <div className="flex items-start gap-3">
          <span className="flex size-10 items-center justify-center rounded-xl bg-(--color-hover) text-(--color-text-secondary)">
            <Shield aria-hidden="true" className="size-5" />
          </span>
          <p className="text-sm text-(--color-text-secondary)">
            Pin a machine with Always allow on the Accept dialog and it will skip the
            prompt next time.
          </p>
        </div>
      ) : (
        <ul className="flex flex-col gap-3">
          {trusted.map((entry) => (
            <li key={entry.address} className="animate-fade-in flex items-center gap-3">
              <DeviceAvatar name={entry.machineName} />
              <div className="min-w-0 flex-1">
                <p className="truncate font-medium">{entry.machineName}</p>
                <p className="text-sm text-(--color-text-secondary)">
                  Last used {formatRelative(entry.lastConnectedMs)}
                </p>
              </div>
              <Button
                variant="primary"
                size="sm"
                disabled={busy}
                onClick={() => {
                  onConnect(entry.address);
                }}
              >
                Connect
              </Button>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
