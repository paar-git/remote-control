/**
 * Home: connect to a device, this machine, and a compact recent list.
 */

import { useCallback, useEffect, useState } from 'react';

import { parseAddress } from './address.js';
import {
  connectToAddress,
  describeConnectionState,
  getClientInfo,
  getHostStatus,
  getLocalIdentity,
  isBusy,
  isConnected,
  listRecent,
  setAccepting,
  type ClientInfo,
  type ConnectionState,
  type HostStatus,
  type LocalIdentity,
  type Recent,
} from './api.js';
import { formatRelative } from './format.js';
import { ThisDevice } from './ThisDevice';
import { Button, Card, EmptyState, TextField, type Toast } from './ui';

export function RemoteControlPage({
  connection,
  onConnected,
  onToast,
  onViewAllDevices,
}: {
  readonly connection: ConnectionState;
  readonly onConnected: () => void;
  readonly onToast: (toast: Toast) => void;
  readonly onViewAllDevices: () => void;
}): React.JSX.Element {
  const [address, setAddress] = useState('');
  const [parseError, setParseError] = useState<string | null>(null);
  const [status, setStatus] = useState<HostStatus | null>(null);
  const [identity, setIdentity] = useState<LocalIdentity | null>(null);
  const [os, setOs] = useState<ClientInfo['osFamily'] | undefined>(undefined);
  const [hostname, setHostname] = useState<string | undefined>(undefined);
  const [recent, setRecent] = useState<readonly Recent[]>([]);
  const [toggling, setToggling] = useState(false);

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
    listRecent()
      .then(setRecent)
      .catch(() => {
        setRecent([]);
      });
  }, [onToast]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    if (isConnected(connection)) onConnected();
  }, [connection, onConnected]);

  const busy = isBusy(connection);
  const failed = connection.state === 'refused' || connection.state === 'failed';

  const connect = (target: string): void => {
    setParseError(null);
    connectToAddress(target, null).catch((error: unknown) => {
      onToast({
        kind: 'error',
        message: error instanceof Error ? error.message : 'Could not start the connection.',
      });
    });
  };

  const submit = (): void => {
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
            error={parseError}
            trailing={
              <Button type="submit" variant="primary" size="lg" disabled={busy}>
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
          <EmptyState title="No recent devices" body="Connections you make will appear here." />
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
