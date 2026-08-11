/**
 * Remote Access — the computers you have saved.
 *
 * Modelled on Chrome Remote Desktop's device list, and on the same principle: the whole
 * screen is a list of machines, and one click on a machine starts a session. Everything
 * that is not "which computer" is either an icon action on the row or lives somewhere
 * else entirely.
 *
 * The row itself is the connect button. Rename and revoke are separate controls placed
 * outside it, because a destructive action must never be something you can hit by
 * aiming slightly wrong at the thing you actually wanted.
 */

import { MonitorSmartphone, Pencil, Trash2 } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';

import {
  ROLE_LABELS,
  type ConnectionState,
  type TrustedDevice,
  connectToServer,
  describeConnectionState,
  disconnectFromServer,
  isBusy,
  isConnected,
  listTrustedDevices,
  renameTrustedDevice,
  revokeTrustedDevice,
} from './api.js';
import { formatFingerprintGroups, formatRelative } from './format.js';
import { type Connection, connectionTone } from './useConnection.js';
import {
  Badge,
  Button,
  ConfirmDialog,
  EmptyState,
  ErrorState,
  IconButton,
  PageHeader,
  SectionHeading,
  Skeleton,
  StatusBadge,
  StatusDot,
  type Toast,
} from './ui';

type LoadState =
  | { readonly status: 'loading' }
  | { readonly status: 'ready'; readonly devices: readonly TrustedDevice[] }
  | { readonly status: 'error'; readonly message: string };

export function RemoteAccessScreen({
  onToast,
  connection,
  onOpenSession,
}: {
  readonly onToast: (toast: Toast) => void;
  readonly connection: Connection;
  /** Called once a connection is live, to hand the window over to the session. */
  readonly onOpenSession: (deviceName: string | null) => void;
}): React.JSX.Element {
  const [state, setState] = useState<LoadState>({ status: 'loading' });
  const [connectingTo, setConnectingTo] = useState<string | null>(null);
  const [renaming, setRenaming] = useState<string | null>(null);
  const [draftName, setDraftName] = useState('');
  const [pendingRevoke, setPendingRevoke] = useState<TrustedDevice | null>(null);

  const setConnection = connection.set;
  const live = isConnected(connection.state);

  const reload = useCallback(() => {
    listTrustedDevices()
      .then((devices) => {
        setState({ status: 'ready', devices });
      })
      .catch((error: unknown) => {
        setState({
          status: 'error',
          message: error instanceof Error ? error.message : 'Could not load your computers.',
        });
      });
  }, []);

  useEffect(reload, [reload]);

  const doConnect = useCallback(
    (device: TrustedDevice) => {
      setConnectingTo(device.deviceId);
      connectToServer(device.deviceId)
        .then((next) => {
          setConnection(next);
          if (next.state === 'connected') {
            reload();
            // The session takes the window as soon as there is one, exactly as
            // clicking a computer in Chrome Remote Desktop does.
            onOpenSession(device.displayName);
          } else if (next.state === 'refused' || next.state === 'failed') {
            onToast({ kind: 'error', message: describeConnectionState(next) });
          }
        })
        .catch((error: unknown) => {
          onToast({
            kind: 'error',
            message: error instanceof Error ? error.message : 'Could not connect.',
          });
        })
        .finally(() => {
          setConnectingTo(null);
        });
    },
    [onOpenSession, onToast, reload, setConnection],
  );

  const doDisconnect = useCallback(() => {
    disconnectFromServer()
      .then((next) => {
        setConnection(next);
        onToast({ kind: 'success', message: 'Disconnected. It will not reconnect on its own.' });
      })
      .catch((error: unknown) => {
        onToast({
          kind: 'error',
          message: error instanceof Error ? error.message : 'Could not disconnect.',
        });
      });
  }, [onToast, setConnection]);

  const doRename = useCallback(
    (deviceId: string, name: string) => {
      renameTrustedDevice(deviceId, name)
        .then(() => {
          setRenaming(null);
          reload();
        })
        .catch((error: unknown) => {
          onToast({
            kind: 'error',
            message: error instanceof Error ? error.message : 'Could not rename the computer.',
          });
        });
    },
    [onToast, reload],
  );

  const doRevoke = useCallback(
    (device: TrustedDevice) => {
      setPendingRevoke(null);
      revokeTrustedDevice(device.deviceId)
        .then(() => {
          onToast({ kind: 'success', message: `Access revoked for ${device.displayName}.` });
          reload();
        })
        .catch((error: unknown) => {
          onToast({
            kind: 'error',
            message: error instanceof Error ? error.message : 'Could not revoke the computer.',
          });
        });
    },
    [onToast, reload],
  );

  if (state.status === 'loading') {
    return (
      <div className="mx-auto w-full max-w-3xl">
        <PageHeader title="Remote Access" />
        <div className="flex flex-col gap-3">
          {[0, 1].map((index) => (
            <Skeleton key={index} className="h-[68px] rounded-xl" />
          ))}
        </div>
      </div>
    );
  }

  if (state.status === 'error') {
    return (
      <div className="mx-auto w-full max-w-3xl">
        <PageHeader title="Remote Access" />
        <ErrorState
          summary="Your saved computers couldn’t be loaded."
          detail={state.message}
          onRetry={reload}
        />
      </div>
    );
  }

  const active = state.devices.filter((device) => !device.revoked);
  const revoked = state.devices.filter((device) => device.revoked);

  return (
    <div className="animate-fade-in mx-auto flex w-full max-w-3xl flex-col gap-8">
      <PageHeader
        title="Remote Access"
        meta={
          connection.state.state === 'offline' ? undefined : (
            <StatusBadge tone={connectionTone(connection.state)}>
              {describeConnectionState(connection.state)}
            </StatusBadge>
          )
        }
        actions={
          live ? (
            <Button
              variant="primary"
              onClick={() => {
                onOpenSession(null);
              }}
            >
              Open session
            </Button>
          ) : undefined
        }
      />

      <section>
        <SectionHeading title="Remote devices" />

        {active.length === 0 ? (
          <EmptyState
            icon={MonitorSmartphone}
            title="No computers yet"
            body="Computers you can reach will appear here, ready to connect to whenever you need them."
          />
        ) : (
          <ul className="flex flex-col gap-3">
            {active.map((device) => (
              <DeviceRow
                key={device.deviceId}
                device={device}
                connection={connection.state}
                busy={connectingTo === device.deviceId}
                renaming={renaming === device.deviceId}
                draftName={draftName}
                onDraftName={setDraftName}
                onConnect={() => {
                  doConnect(device);
                }}
                onDisconnect={doDisconnect}
                onStartRename={() => {
                  setRenaming(device.deviceId);
                  setDraftName(device.displayName);
                }}
                onCancelRename={() => {
                  setRenaming(null);
                }}
                onCommitRename={() => {
                  doRename(device.deviceId, draftName);
                }}
                onRevoke={() => {
                  setPendingRevoke(device);
                }}
              />
            ))}
          </ul>
        )}
      </section>

      {revoked.length > 0 && (
        <section>
          <SectionHeading
            title="Revoked"
            description="Kept so the activity history stays complete. These cannot connect."
          />
          <ul className="flex flex-col gap-2">
            {revoked.map((device) => (
              <li
                key={device.deviceId}
                className="flex items-center gap-3 rounded-xl border border-(--color-border-subtle) px-4 py-3 opacity-60"
              >
                <MonitorSmartphone
                  aria-hidden="true"
                  className="size-4 shrink-0 text-(--color-text-muted)"
                />
                <span className="min-w-0 flex-1 truncate text-sm">{device.displayName}</span>
                <StatusBadge tone="danger">Revoked</StatusBadge>
              </li>
            ))}
          </ul>
        </section>
      )}

      <ConfirmDialog
        open={pendingRevoke !== null}
        title="Remove this computer?"
        destructive
        confirmLabel="Remove access"
        body={
          pendingRevoke === null ? null : (
            <>
              <p className="mb-2">
                <strong className="text-(--color-text-primary)">{pendingRevoke.displayName}</strong>{' '}
                will no longer be able to connect. This takes effect immediately.
              </p>
              <p className="mb-2 font-mono text-xs break-all">
                {formatFingerprintGroups(pendingRevoke.identityFingerprint)}
              </p>
              <p>This cannot be undone from here.</p>
            </>
          )
        }
        onConfirm={() => {
          if (pendingRevoke !== null) doRevoke(pendingRevoke);
        }}
        onCancel={() => {
          setPendingRevoke(null);
        }}
      />
    </div>
  );
}

/**
 * One computer.
 *
 * The whole row is the connect control. It reports what it is doing in place — the
 * operator clicked *this* machine, so this is where the answer belongs, not in a banner
 * somewhere else on the page.
 */
function DeviceRow({
  device,
  connection,
  busy,
  renaming,
  draftName,
  onDraftName,
  onConnect,
  onDisconnect,
  onStartRename,
  onCancelRename,
  onCommitRename,
  onRevoke,
}: {
  readonly device: TrustedDevice;
  readonly connection: ConnectionState;
  readonly busy: boolean;
  readonly renaming: boolean;
  readonly draftName: string;
  readonly onDraftName: (name: string) => void;
  readonly onConnect: () => void;
  readonly onDisconnect: () => void;
  readonly onStartRename: () => void;
  readonly onCancelRename: () => void;
  readonly onCommitRename: () => void;
  readonly onRevoke: () => void;
}): React.JSX.Element {
  const live = isConnected(connection);
  const blocked = busy || (isBusy(connection) && !live);

  if (renaming) {
    return (
      <li className="rounded-xl border border-(--color-accent)/40 bg-(--color-surface-raised) p-4">
        <form
          onSubmit={(event) => {
            event.preventDefault();
            onCommitRename();
          }}
          className="flex flex-wrap items-center gap-2"
        >
          <label htmlFor={`rename-${device.deviceId}`} className="sr-only">
            New name for {device.displayName}
          </label>
          <input
            id={`rename-${device.deviceId}`}
            value={draftName}
            onChange={(event) => {
              onDraftName(event.target.value);
            }}
            maxLength={128}
            autoFocus
            className="h-9 min-w-0 flex-1 rounded-lg border border-(--color-border-strong) bg-(--color-surface) px-3 text-sm"
          />
          <Button type="submit" variant="primary">
            Save
          </Button>
          <Button variant="ghost" onClick={onCancelRename}>
            Cancel
          </Button>
        </form>
      </li>
    );
  }

  return (
    <li className="group/row relative">
      <button
        type="button"
        onClick={live ? onDisconnect : onConnect}
        disabled={blocked}
        aria-label={
          live ? `Disconnect from ${device.displayName}` : `Connect to ${device.displayName}`
        }
        className="flex w-full cursor-pointer items-center gap-4 rounded-xl border border-(--color-border-subtle) bg-(--color-surface-raised) py-4 pr-24 pl-4 text-left transition-[background-color,border-color] duration-150 ease-(--ease-ui) hover:border-(--color-border-strong) hover:bg-(--color-surface-overlay) active:translate-y-px disabled:pointer-events-none disabled:opacity-60"
      >
        <span
          className={`flex size-10 shrink-0 items-center justify-center rounded-xl transition-colors duration-150 ease-(--ease-ui) ${
            live
              ? 'bg-(--color-success-soft) text-(--color-success)'
              : 'bg-(--color-surface-overlay) text-(--color-text-secondary) group-hover/row:bg-(--color-accent-soft) group-hover/row:text-(--color-accent)'
          }`}
        >
          <MonitorSmartphone aria-hidden="true" className="size-5" />
        </span>

        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-center gap-2">
            <span className="truncate text-[15px] font-medium">{device.displayName}</span>
            <Badge>{ROLE_LABELS[device.role]}</Badge>
          </span>
          <span className="mt-0.5 flex items-center gap-1.5 text-xs text-(--color-text-secondary)">
            <StatusDot tone={live ? 'ready' : busy ? 'busy' : 'idle'} />
            {busy
              ? describeConnectionState(connection)
              : live
                ? 'Connected — click to disconnect'
                : device.lastAuthenticatedAtMs === null
                  ? 'Never connected'
                  : `Last connected ${formatRelative(device.lastAuthenticatedAtMs).toLowerCase()}`}
          </span>
        </span>
      </button>

      {/* Outside the connect button, so a mis-aimed click cannot revoke a computer. */}
      <div className="absolute top-1/2 right-4 flex -translate-y-1/2 gap-1">
        <IconButton icon={Pencil} label={`Rename ${device.displayName}`} onClick={onStartRename} />
        <IconButton icon={Trash2} label={`Remove ${device.displayName}`} onClick={onRevoke} />
      </div>
    </li>
  );
}
