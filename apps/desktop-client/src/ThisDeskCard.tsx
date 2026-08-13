/**
 * This machine: where it can be reached, and whether it is listening.
 *
 * The left card of the main window. Everything here is something the user reads out to
 * someone else, so addresses render in the monospace stack and each has its own copy
 * control — a single "copy" on a card with three addresses is a guess about which one
 * they meant.
 */

import { Monitor } from 'lucide-react';

import { displayAddress } from './address.js';
import type { HostStatus } from './api.js';
import { Card, CardHeader, CopyButton } from './ui';

export function ThisDeskCard({
  status,
}: {
  /** `null` until the backend has answered. */
  readonly status: HostStatus | null;
}): React.JSX.Element {
  return (
    <Card>
      <CardHeader icon={Monitor} title="This desk" />

      {status === null ? (
        <p className="text-sm text-(--color-text-secondary)">Reading this machine’s state…</p>
      ) : (
        <>
          <p className="mb-1 truncate text-base font-semibold" title={status.machineName}>
            {status.machineName}
          </p>

          <p className="mb-3 flex items-center gap-2 text-sm text-(--color-text-secondary)">
            <span
              aria-hidden="true"
              className={`size-2 shrink-0 rounded-full ${
                status.accepting ? 'bg-(--color-success)' : 'bg-(--color-text-secondary)'
              }`}
            />
            {status.accepting ? 'Accepting connections' : 'Not accepting connections'}
          </p>

          {status.addresses.length === 0 ? (
            /*
             * Honest rather than helpful-looking. A machine with no usable address gets
             * nothing to copy, because a placeholder here would be read out to someone
             * on the phone and would not work.
             */
            <p className="text-sm text-(--color-text-secondary)">
              This machine has no network address, so nobody can reach it yet.
            </p>
          ) : (
            <ul className="flex flex-col gap-1.5">
              {status.addresses.map((address) => (
                <li key={address} className="flex items-center gap-2">
                  <code className="min-w-0 flex-1 truncate font-mono text-sm">
                    {displayAddress(address)}
                  </code>
                  <CopyButton value={displayAddress(address)} label="address" size="sm" />
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </Card>
  );
}
