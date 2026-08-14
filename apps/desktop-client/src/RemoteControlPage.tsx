/**
 * Home: connect to a device, this machine, and a compact recent list.
 */

import { useCallback, useEffect, useState } from 'react';

import { LoaderCircle } from 'lucide-react';

import { parseAddress } from './address.js';
import {
  connectToAddress,
  describeConnectionState,
  getClientInfo,
  getConnectionState,
  getHostStatus,
  getLocalIdentity,
  isBusy,
  isConnected,
  listRecent,
  probeDevice,
  setAccepting,
  type ClientInfo,
  type ConnectionState,
  type HostStatus,
  type LocalIdentity,
  type Presence,
  type Recent,
} from './api.js';
import { formatRelative } from './format.js';
import { ThisDevice } from './ThisDevice';
import { Button, Card, StatusBadge, TextField, type Toast } from './ui';

export function RemoteControlPage({
  connection,
  onConnection,
  onConnected,
  onToast,
  onViewAllDevices,
  hostEpoch = 0,
}: {
  readonly connection: ConnectionState;
  readonly onConnection: (next: ConnectionState) => void;
  readonly onConnected: () => void;
  readonly onToast: (toast: Toast) => void;
  readonly onViewAllDevices: () => void;
  /** Bumped when something outside this page changes host status (e.g. emergency stop). */
  readonly hostEpoch?: number | undefined;
}): React.JSX.Element {
  const [address, setAddress] = useState('');
  const [parseError, setParseError] = useState<string | null>(null);
  const [status, setStatus] = useState<HostStatus | null>(null);
  const [identity, setIdentity] = useState<LocalIdentity | null>(null);
  const [os, setOs] = useState<ClientInfo['osFamily'] | undefined>(undefined);
  const [hostname, setHostname] = useState<string | undefined>(undefined);
  const [recent, setRecent] = useState<readonly Recent[]>([]);
  const [presence, setPresence] = useState<Readonly<Record<string, Presence>>>({});
  const [toggling, setToggling] = useState(false);
  const [dialing, setDialing] = useState(false);

  const refresh = useCallback(() => {
    getHostStatus()
      .then(setStatus)
      .catch((error: unknown) => {
        onToast({
          kind: 'error',
          message: error instanceof Error ? error.message : 'Could not read this machine’s state.',
        });
      });
    getLocalIdentity()
      .then(setIdentity)
      .catch(() => {
        setIdentity(null);
      });
    getClientInfo()
      .then((info) => {
        setOs(info.osFamily);
        setHostname(info.hostname);
      })
      .catch(() => {
        setOs(undefined);
        setHostname(undefined);
      });
    let cancelled = false;
    listRecent()
      .then((entries) => {
        if (cancelled) return;
        setRecent(entries);
        for (const entry of entries.slice(0, 5)) {
          setPresence((current) => ({ ...current, [entry.address]: 'checking' }));
          probeDevice(entry.address)
            .then((result) => {
              if (!cancelled) {
                setPresence((current) => ({ ...current, [entry.address]: result }));
              }
            })
            .catch(() => {
              if (!cancelled) {
                setPresence((current) => ({ ...current, [entry.address]: 'offline' }));
              }
            });
        }
      })
      .catch(() => {
        if (!cancelled) setRecent([]);
      });
    return () => {
      cancelled = true;
    };
  }, [onToast]);

  useEffect(() => {
    const stop = refresh();
    return stop;
  }, [refresh, hostEpoch]);

  useEffect(() => {
    if (isConnected(connection)) onConnected();
  }, [connection, onConnected]);

  const busy = isBusy(connection) || dialing;
  const failed = connection.state === 'refused' || connection.state === 'failed';

  const connect = (target: string): void => {
    if (busy) return;
    setParseError(null);
    setDialing(true);
    connectToAddress(target, null)
      .then((next) => {
        onConnection(next);
      })
      .catch((error: unknown) => {
        onToast({
          kind: 'error',
          message: error instanceof Error ? error.message : 'Could not start the connection.',
        });
        getConnectionState()
          .then(onConnection)
          .catch(() => undefined);
      })
      .finally(() => {
        setDialing(false);
      });
  };

  const submit = (): void => {
    const trimmed = address.trim();
    if (/^\d{3}\s?\d{3}\s?\d{3}$/.test(trimmed) || /^\d{9}$/.test(trimmed.replace(/\s/g, ''))) {
      setParseError(
        'A device ID identifies a machine. Type its hostname or IP address to connect — there is no directory to look the ID up in.',
      );
      return;
    }
    const parsed = parseAddress(address);
    if (!parsed.ok) {
      setParseError(parsed.reason);
      return;
    }
    connect(parsed.value);
  };

  const toggleAccepting = (next: boolean): void => {
    setToggling(true);
    setAccepting(next)
      .then(setStatus)
      .catch((error: unknown) => {
        onToast({
          kind: 'error',
          message:
            error instanceof Error ? error.message : 'Could not change incoming connections.',
        });
      })
      .finally(() => {
        setToggling(false);
      });
  };

  const shown = recent.slice(0, 5);

  return (
    <div className="mx-auto flex w-full max-w-3xl flex-col gap-6">
      <Card>
        <h2 className="mb-4 text-2xl font-semibold tracking-tight">Connect to a device</h2>
        <form
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            submit();
          }}
        >
          <TextField
            label="Device ID, hostname, or IP address"
            value={address}
            onChange={(value) => {
              setAddress(value);
              setParseError(null);
            }}
            placeholder="192.168.1.77"
            mono
            autoComplete="off"
            help="Type a hostname or IP address. The Device ID is for verifying identity, not for connecting."
            error={parseError}
            trailing={
              <Button type="submit" variant="primary" size="lg" disabled={busy}>
                {busy ? <LoaderCircle aria-hidden="true" className="size-4 animate-spin" /> : null}
                Connect
              </Button>
            }
          />
        </form>
        <p role="status" className="mt-3 text-sm text-(--color-text-secondary)">
          {describeConnectionState(connection)}
        </p>
        {failed && (
          <p role="alert" className="mt-2 text-sm text-(--color-danger)">
            {connection.message}
          </p>
        )}
      </Card>

      {status !== null && (
        <ThisDevice
          status={status}
          identity={identity}
          os={os}
          hostname={hostname}
          onToggleAccepting={toggleAccepting}
          toggling={toggling}
        />
      )}

      <section>
        <div className="mb-3 flex items-center justify-between gap-3">
          <h2 className="text-base font-semibold">Recent</h2>
          {recent.length > 5 && (
            <Button variant="ghost" size="sm" onClick={onViewAllDevices}>
              View all devices
            </Button>
          )}
        </div>
        {shown.length === 0 ? (
          <p className="text-sm text-(--color-text-secondary)">No recent devices.</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {shown.map((entry) => (
              <li
                key={entry.address}
                data-testid="recent-device"
                className="flex items-center justify-between gap-3 rounded-xl border border-(--color-border) bg-(--color-card) px-4 py-3"
              >
                <div className="min-w-0">
                  <p className="truncate font-medium">{entry.machineName}</p>
                  <p className="truncate font-mono text-xs text-(--color-text-secondary)">
                    {entry.address}
                  </p>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  <RecentPresence presence={presence[entry.address] ?? 'checking'} />
                  <span className="text-xs text-(--color-text-secondary)">
                    {formatRelative(entry.lastConnectedMs)}
                  </span>
                  <Button
                    variant="subtle"
                    size="sm"
                    disabled={busy}
                    onClick={() => {
                      connect(entry.address);
                    }}
                  >
                    Connect
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
        {recent.length > 0 && recent.length <= 5 && (
          <div className="mt-3">
            <Button variant="ghost" size="sm" onClick={onViewAllDevices}>
              View all devices
            </Button>
          </div>
        )}
      </section>
    </div>
  );
}

function RecentPresence({ presence }: { readonly presence: Presence }): React.JSX.Element {
  if (presence === 'checking') {
    return <StatusBadge tone="busy">Checking…</StatusBadge>;
  }
  if (presence === 'online') {
    return <StatusBadge tone="ready">Online</StatusBadge>;
  }
  return <StatusBadge tone="idle">Offline</StatusBadge>;
}
