/**
 * This machine: name, readiness, a readable device id, and a real incoming-connection switch.
 *
 * Raw addresses live under Advanced. Leading with three IPs made the home screen look
 * like a network panel rather than a place to start a session.
 */

import { ChevronDown, Share2 } from 'lucide-react';
import { useState } from 'react';

import { displayAddress } from './address.js';
import type { HostStatus } from './api.js';
import { DeviceAvatar } from './DeviceAvatar';
import { formatDeviceId } from './format.js';
import { Button, Card, CopyButton, Toggle } from './ui';

export function ThisDeskCard({
  status,
  deviceIdSource,
  os,
  onToggleAccepting,
  toggling = false,
}: {
  readonly status: HostStatus | null;
  /** Fingerprint or backend device id used to derive the nine-digit display id. */
  readonly deviceIdSource: string | null;
  readonly os?: 'windows' | 'linux' | 'macos' | 'unknown' | undefined;
  readonly onToggleAccepting: (next: boolean) => void;
  readonly toggling?: boolean | undefined;
}): React.JSX.Element {
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const deviceId = deviceIdSource === null ? '—' : formatDeviceId(deviceIdSource);
  const primaryAddress = status?.addresses[0] ?? null;

  const share = (): void => {
    if (status === null) return;
    const lines = [
      status.machineName,
      `Device ID: ${deviceId}`,
      ...(primaryAddress === null ? [] : [`Address: ${displayAddress(primaryAddress)}`]),
    ];
    void navigator.clipboard.writeText(lines.join('\n'));
  };

  return (
    <Card>
      <h2 className="mb-5 text-xl font-semibold tracking-tight">This device</h2>

      {status === null ? (
        <p className="text-sm text-(--color-text-secondary)">Reading this machine’s state…</p>
      ) : (
        <div className="flex flex-col gap-5">
          <div className="flex items-start gap-3">
            <DeviceAvatar name={status.machineName} os={os} />
            <div className="min-w-0">
              <p className="truncate text-lg font-semibold" title={status.machineName}>
                {status.machineName}
              </p>
              <p className="mt-0.5 flex items-center gap-2 text-sm text-(--color-text-secondary)">
                <span
                  aria-hidden="true"
                  className={
                    'size-2 shrink-0 rounded-full transition-colors duration-200 animate-status-dot ' +
                    (status.accepting ? 'bg-(--color-success)' : 'bg-(--color-text-secondary)')
                  }
                />
                {status.accepting ? 'Ready for connections' : 'Not accepting connections'}
              </p>
            </div>
          </div>

          <div>
            <p className="mb-1 text-sm text-(--color-text-secondary)">Device ID</p>
            <p className="font-mono text-lg tracking-wide">{deviceId}</p>
            <div className="mt-2 flex flex-wrap gap-2">
              <CopyButton value={deviceId} label="device ID" size="sm" />
              <Button variant="default" size="sm" icon={Share2} onClick={share}>
                Share
              </Button>
            </div>
          </div>

          <div className="flex items-start justify-between gap-4 border-t border-(--color-border) pt-4">
            <div className="min-w-0">
              <p className="text-sm font-medium">Allow incoming connections</p>
              <p className="mt-1 text-sm text-(--color-text-secondary)">
                {status.accepting
                  ? 'This PC is reachable on the local network. Anyone with an address below can request a session.'
                  : 'Incoming requests are refused. Turn this on when you want someone to connect to this PC.'}
              </p>
            </div>
            <Toggle
              checked={status.accepting}
              disabled={toggling}
              label="Allow incoming connections"
              onChange={onToggleAccepting}
            />
          </div>

          <div>
            <button
              type="button"
              aria-expanded={advancedOpen}
              onClick={() => {
                setAdvancedOpen((open) => !open);
              }}
              className="flex items-center gap-1.5 text-sm font-medium text-(--color-text-secondary) transition-colors duration-150 hover:text-(--color-text)"
            >
              Advanced network info
              <ChevronDown
                aria-hidden="true"
                className={`size-4 transition-transform duration-200 ${advancedOpen ? 'rotate-180' : ''}`}
              />
            </button>
            {advancedOpen && (
              <div className="animate-fade-in mt-3">
                {status.addresses.length === 0 ? (
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
              </div>
            )}
          </div>
        </div>
      )}
    </Card>
  );
}
