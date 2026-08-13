/**
 * Machines connected to before.
 *
 * Each row is one button, not a row with a button in it: the whole thing is the target,
 * and clicking anywhere on it connects. The per-row menu is deliberately absent — the
 * two things you can do to an entry (always-allow, forget) live in the settings dialog,
 * so a mis-click in the list cannot change what a machine is permitted to do.
 */

import { Clock } from 'lucide-react';

import { displayAddress } from './address.js';
import type { Recent } from './api.js';
import { formatRelative } from './format.js';
import { Card, CardHeader, EmptyState } from './ui';

export function RecentList({
  entries,
  onConnect,
  busy,
}: {
  readonly entries: readonly Recent[];
  /** Given the canonical `host:port` already stored for the entry. */
  readonly onConnect: (address: string) => void;
  readonly busy: boolean;
}): React.JSX.Element {
  return (
    <Card>
      <CardHeader icon={Clock} title="Recent" />

      {entries.length === 0 ? (
        <EmptyState
          title="Nothing yet"
          body="Machines you connect to will appear here, ready to reconnect in one click."
        />
      ) : (
        <ul className="flex flex-col gap-1">
          {entries.map((entry) => (
            <li key={entry.address}>
              <button
                type="button"
                disabled={busy}
                onClick={() => {
                  onConnect(entry.address);
                }}
                className={
                  'flex w-full items-center gap-3 rounded-lg px-2 py-2 text-left ' +
                  'transition-colors duration-150 ease-(--ease-ui) ' +
                  'hover:bg-(--color-hover) disabled:pointer-events-none disabled:opacity-45 ' +
                  'focus-visible:outline-2 focus-visible:outline-offset-2 ' +
                  'focus-visible:outline-(--color-accent)'
                }
              >
                <span className="min-w-0 flex-1">
                  {/*
                   * Chosen by the other machine. `untrustedText` in the schema has
                   * already stripped the control characters and bidi overrides that
                   * would let it render as a different name.
                   */}
                  <span className="block truncate text-sm font-medium">{entry.machineName}</span>
                  <code className="block truncate font-mono text-xs text-(--color-text-secondary)">
                    {displayAddress(entry.address)}
                  </code>
                </span>
                <span className="shrink-0 text-xs text-(--color-text-secondary)">
                  {formatRelative(entry.lastConnectedMs)}
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
