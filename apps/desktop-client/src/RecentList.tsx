/**
 * Machines connected to before, as compact device cards.
 *
 * Online/offline is not shown: this product has no presence channel, and a grey dot
 * pretending a machine is offline would be a lie. Last-connected time is the fact we
 * actually have.
 */

import { Monitor } from 'lucide-react';

import { displayAddress } from './address.js';
import type { Recent } from './api.js';
import { DeviceAvatar } from './DeviceAvatar';
import { formatRelative } from './format.js';
import { Button, Card } from './ui';

export function RecentList({
  entries,
  onConnect,
  busy,
}: {
  readonly entries: readonly Recent[];
  readonly onConnect: (address: string) => void;
  readonly busy: boolean;
}): React.JSX.Element {
  return (
    <section id="recent-sessions" className="flex flex-col gap-4">
      <h2 className="text-xl font-semibold tracking-tight">Recent sessions</h2>

      {entries.length === 0 ? (
        <div className="flex items-center gap-3 rounded-[var(--radius-card)] border border-dashed border-(--color-border) px-4 py-4">
          <span className="flex size-10 items-center justify-center rounded-xl bg-(--color-hover) text-(--color-text-secondary)">
            <Monitor aria-hidden="true" className="size-5" />
          </span>
          <div>
            <p className="text-sm font-medium">No recent devices.</p>
            <p className="text-sm text-(--color-text-secondary)">
              Machines you connect to appear here for one-click reconnect.
            </p>
          </div>
        </div>
      ) : (
        <Card padded={false}>
          <ul>
            {entries.map((entry, index) => (
              <li
                key={entry.address}
                className={
                  'animate-fade-in flex items-center gap-3 px-5 py-3.5 ' +
                  (index > 0 ? 'border-t border-(--color-border) ' : '')
                }
              >
                <DeviceAvatar name={entry.machineName} />
                <div className="min-w-0 flex-1">
                  <p className="truncate font-medium">{entry.machineName}</p>
                  <p className="truncate text-sm text-(--color-text-secondary)">
                    {displayAddress(entry.address)} · {formatRelative(entry.lastConnectedMs)}
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
        </Card>
      )}
    </section>
  );
}
