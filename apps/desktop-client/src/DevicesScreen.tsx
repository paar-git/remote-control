/**
 * The Devices screen.
 *
 * Everything shown here is real, persisted state read through validated commands, and
 * every button performs the operation it names: pairing runs the real exchange over the
 * network, and Connect opens a real authenticated session.
 *
 * Two presentation rules this screen holds to:
 *
 * * A **discovered** server is labelled as claiming its name and fingerprint, because
 *   anyone on the network can announce anything. The pinned value, once paired, is
 *   presented differently.
 * * A refused connection is shown with the reason and what to do about it, never as a
 *   generic failure. A server whose identity changed is the loudest case on the screen.
 */

import { useCallback, useEffect, useState } from 'react';

import {
  ROLE_LABELS,
  type ConnectionState,
  type DiscoveredAgent,
  type LocalIdentity,
  type TrustedDevice,
  checkPairingCodeFormat,
  connectToServer,
  describeConnectionState,
  disconnectFromServer,
  discoverAgents,
  getConnectionState,
  getLocalIdentity,
  isBusy,
  isConnected,
  listTrustedDevices,
  pairWithServer,
  reconnectToServer,
  renameTrustedDevice,
  revokeTrustedDevice,
} from './api.js';
import { Badge, Button, ConfirmDialog, CopyButton, EmptyState, type Toast } from './components';
import {
  abbreviateFingerprint,
  formatFingerprintGroups,
  formatRelative,
  formatTimestamp,
  humanise,
} from './format.js';

type LoadState =
  | { readonly status: 'loading' }
  | {
      readonly status: 'ready';
      readonly devices: TrustedDevice[];
      readonly identity: LocalIdentity | null;
    }
  | { readonly status: 'error'; readonly message: string };

export default function DevicesScreen({
  onToast,
}: {
  readonly onToast: (toast: Toast) => void;
}): React.JSX.Element {
  const [state, setState] = useState<LoadState>({ status: 'loading' });
  const [pendingRevoke, setPendingRevoke] = useState<TrustedDevice | null>(null);
  const [renaming, setRenaming] = useState<string | null>(null);
  const [draftName, setDraftName] = useState('');
  const [connection, setConnection] = useState<ConnectionState>({ state: 'offline' });
  const [connectingTo, setConnectingTo] = useState<string | null>(null);

  const reload = useCallback(() => {
    Promise.all([listTrustedDevices(), getLocalIdentity().catch(() => null)])
      .then(([devices, identity]) => {
        setState({ status: 'ready', devices, identity });
      })
      .catch((error: unknown) => {
        setState({
          status: 'error',
          message: error instanceof Error ? error.message : 'Could not load devices.',
        });
      });
  }, []);

  useEffect(reload, [reload]);

  // The backend owns the connection, so the screen reads it rather than tracking its
  // own copy: a state this screen invented could disagree with what is actually open.
  useEffect(() => {
    let cancelled = false;
    const read = (): void => {
      getConnectionState()
        .then((next) => {
          if (!cancelled) setConnection(next);
        })
        .catch(() => {
          // A failed poll says nothing about the connection; leaving the last known
          // state is better than flickering to "offline".
        });
    };

    read();
    const timer = window.setInterval(read, 1000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  const doConnect = useCallback(
    (device: TrustedDevice) => {
      setConnectingTo(device.deviceId);
      connectToServer(device.deviceId)
        .then((next) => {
          setConnection(next);
          if (next.state === 'connected') {
            onToast({ kind: 'success', message: `Connected to ${device.displayName}.` });
            reload();
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
    [onToast, reload],
  );

  const doDisconnect = useCallback(() => {
    disconnectFromServer()
      .then((next) => {
        setConnection(next);
        onToast({
          kind: 'success',
          message: 'Disconnected. It will not reconnect on its own.',
        });
      })
      .catch((error: unknown) => {
        onToast({
          kind: 'error',
          message: error instanceof Error ? error.message : 'Could not disconnect.',
        });
      });
  }, [onToast]);

  const doReconnect = useCallback(
    (deviceId: string) => {
      setConnectingTo(deviceId);
      reconnectToServer(deviceId)
        .then(setConnection)
        .catch((error: unknown) => {
          onToast({
            kind: 'error',
            message: error instanceof Error ? error.message : 'Could not reconnect.',
          });
        })
        .finally(() => {
          setConnectingTo(null);
        });
    },
    [onToast],
  );

  const doRename = useCallback(
    (deviceId: string, name: string) => {
      renameTrustedDevice(deviceId, name)
        .then(() => {
          setRenaming(null);
          onToast({ kind: 'success', message: 'Device renamed.' });
          reload();
        })
        .catch((error: unknown) => {
          onToast({
            kind: 'error',
            message: error instanceof Error ? error.message : 'Could not rename the device.',
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
            message: error instanceof Error ? error.message : 'Could not revoke the device.',
          });
        });
    },
    [onToast, reload],
  );

  if (state.status === 'loading') {
    return (
      <p role="status" className="text-sm text-(--color-text-secondary)">
        Loading devices…
      </p>
    );
  }

  if (state.status === 'error') {
    return (
      <div role="alert" className="max-w-prose rounded border border-(--color-danger) p-4 text-sm">
        <h2 className="mb-1 font-semibold text-(--color-danger)">Could not load devices</h2>
        <p className="text-(--color-text-secondary)">{state.message}</p>
        <div className="mt-3">
          <Button onClick={reload}>Try again</Button>
        </div>
      </div>
    );
  }

  const { devices, identity } = state;
  const active = devices.filter((d) => !d.revoked);
  const revoked = devices.filter((d) => d.revoked);

  return (
    <section>
      <header className="mb-6">
        <h2 className="text-base font-semibold">Devices</h2>
        <p className="max-w-prose text-sm text-(--color-text-secondary)">
          Servers this computer is paired with. Pairing establishes a cryptographic identity that is
          pinned — a server whose identity changes is rejected, never silently re-trusted.
        </p>
      </header>

      <ConnectionBanner
        state={connection}
        busy={connectingTo !== null}
        onDisconnect={doDisconnect}
        onReconnect={() => {
          const first = active[0];
          if (first !== undefined) doReconnect(first.deviceId);
        }}
      />

      {identity !== null && <ThisDevice identity={identity} />}

      <PairingPanel onPaired={reload} onToast={onToast} />

      <h3 className="mt-8 mb-2 text-sm font-semibold">Paired servers</h3>
      {active.length === 0 ? (
        <EmptyState
          title="No paired servers yet"
          body="Start pairing mode on your server to get a code, then enter it above. Once paired, the server appears here and can be reconnected to without entering the code again."
        />
      ) : (
        <ul className="flex flex-col gap-3">
          {active.map((device) => (
            <DeviceCard
              key={device.deviceId}
              device={device}
              connection={connection}
              busy={connectingTo === device.deviceId}
              onConnect={() => {
                doConnect(device);
              }}
              onDisconnect={doDisconnect}
              renaming={renaming === device.deviceId}
              draftName={draftName}
              onDraftName={setDraftName}
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

      {revoked.length > 0 && (
        <>
          <h3 className="mt-8 mb-2 text-sm font-semibold">Revoked</h3>
          <p className="mb-2 max-w-prose text-sm text-(--color-text-secondary)">
            Revoked devices are kept so the activity history stays complete. They cannot connect.
          </p>
          <ul className="flex flex-col gap-3">
            {revoked.map((device) => (
              <DeviceCard
                key={device.deviceId}
                device={device}
                connection={{ state: 'offline' }}
                busy={false}
                onConnect={() => undefined}
                onDisconnect={() => undefined}
                renaming={false}
                draftName=""
                onDraftName={() => undefined}
                onStartRename={() => undefined}
                onCancelRename={() => undefined}
                onCommitRename={() => undefined}
                onRevoke={() => undefined}
              />
            ))}
          </ul>
        </>
      )}

      <ConfirmDialog
        open={pendingRevoke !== null}
        title="Revoke this device?"
        destructive
        confirmLabel="Revoke access"
        body={
          pendingRevoke === null ? null : (
            <>
              <p className="mb-2">
                <strong>{pendingRevoke.displayName}</strong> will no longer be able to connect. This
                takes effect immediately.
              </p>
              <p className="mb-2 font-mono text-xs break-all">
                {formatFingerprintGroups(pendingRevoke.identityFingerprint)}
              </p>
              <p>Re-pairing with a new code is the only way to restore access.</p>
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
    </section>
  );
}

/** This computer's own identity, which the operator compares during pairing. */
function ThisDevice({ identity }: { readonly identity: LocalIdentity }): React.JSX.Element {
  return (
    <div className="mb-6 rounded border border-(--color-border-subtle) p-4">
      <div className="mb-2 flex items-center justify-between">
        <h3 className="text-sm font-semibold">This computer</h3>
        {identity.needsRenewal && <Badge tone="warning">Certificate renewal due</Badge>}
      </div>
      <dl className="grid gap-x-6 gap-y-1 text-sm sm:grid-cols-[max-content_1fr]">
        <dt className="text-(--color-text-secondary)">Device ID</dt>
        <dd className="font-mono text-xs break-all">{identity.deviceId}</dd>

        <dt className="text-(--color-text-secondary)">Identity fingerprint</dt>
        <dd className="flex items-start gap-2">
          <span className="font-mono text-xs break-all">
            {formatFingerprintGroups(identity.identityFingerprint)}
          </span>
          <CopyButton value={identity.identityFingerprint} label="identity fingerprint" />
        </dd>

        <dt className="text-(--color-text-secondary)">Certificate</dt>
        <dd className="text-xs">
          version {identity.certificateVersion}, valid until{' '}
          {formatTimestamp(identity.certificateNotAfterMs)}
        </dd>
      </dl>
      <p className="mt-3 max-w-prose text-xs text-(--color-text-secondary)">
        The identity fingerprint stays the same when the certificate is renewed. Compare it with
        what your server shows during pairing.
      </p>
    </div>
  );
}

/**
 * The pairing panel: find a server, or type its address, then enter the code.
 *
 * Format is checked against the backend as the operator types, so a mistyped character
 * is caught before a network round trip and before an attempt is spent — codes allow
 * only five.
 */
function PairingPanel({
  onPaired,
  onToast,
}: {
  readonly onPaired: () => void;
  readonly onToast: (toast: Toast) => void;
}): React.JSX.Element {
  const [address, setAddress] = useState('');
  const [name, setName] = useState('');
  const [code, setCode] = useState('');
  const [formatOk, setFormatOk] = useState<boolean | null>(null);
  const [pairing, setPairing] = useState(false);
  const [found, setFound] = useState<DiscoveredAgent[] | null>(null);
  const [searching, setSearching] = useState(false);

  useEffect(() => {
    if (code.trim() === '') {
      setFormatOk(null);
      return;
    }
    let cancelled = false;
    checkPairingCodeFormat(code)
      .then((ok) => {
        if (!cancelled) setFormatOk(ok);
      })
      .catch(() => {
        if (!cancelled) setFormatOk(null);
      });
    return () => {
      cancelled = true;
    };
  }, [code]);

  const search = useCallback(() => {
    setSearching(true);
    discoverAgents()
      .then((agents) => {
        setFound(agents);
      })
      .catch((error: unknown) => {
        onToast({
          kind: 'error',
          message: error instanceof Error ? error.message : 'Could not search the local network.',
        });
      })
      .finally(() => {
        setSearching(false);
      });
  }, [onToast]);

  const submit = useCallback(() => {
    setPairing(true);
    pairWithServer(address, code, name)
      .then((paired) => {
        setCode('');
        setAddress('');
        setName('');
        setFound(null);
        onToast({
          kind: 'success',
          message: `Paired with ${paired.displayName}. Check its fingerprint matches the server: ${paired.identityFingerprint}`,
        });
        onPaired();
      })
      .catch((error: unknown) => {
        onToast({
          kind: 'error',
          message: error instanceof Error ? error.message : 'Pairing failed.',
        });
      })
      .finally(() => {
        setPairing(false);
      });
  }, [address, code, name, onPaired, onToast]);

  const canSubmit = !pairing && formatOk === true && address.trim() !== '';

  return (
    <div className="rounded border border-(--color-border-subtle) p-4">
      <h3 className="mb-1 text-sm font-semibold">Pair a new server</h3>
      <p className="mb-3 max-w-prose text-sm text-(--color-text-secondary)">
        Run <code className="font-mono text-xs">rc-agent pair</code> on the server to display a
        code, then enter it here along with the server’s address.
      </p>

      <div className="mb-3">
        <Button onClick={search} disabled={searching}>
          {searching ? 'Searching…' : 'Search the local network'}
        </Button>
      </div>

      {found !== null && found.length === 0 && (
        <p role="status" className="mb-3 max-w-prose text-xs text-(--color-text-secondary)">
          No servers answered. Many networks block discovery — type the server’s address below
          instead.
        </p>
      )}

      {found !== null && found.length > 0 && (
        <ul className="mb-3 flex flex-col gap-1.5">
          {found.map((agent) => (
            <li
              key={agent.deviceId}
              className="flex flex-wrap items-center gap-2 rounded border border-(--color-border-subtle) px-3 py-2 text-xs"
            >
              <span className="font-medium">{agent.displayName}</span>
              <span className="font-mono text-(--color-text-secondary)">{agent.address}</span>
              {agent.alreadySaved ? (
                <Badge tone="success">Already paired</Badge>
              ) : (
                <Button
                  onClick={() => {
                    setAddress(agent.address);
                    setName(agent.displayName);
                  }}
                >
                  Use this
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}

      <form
        className="flex flex-wrap items-end gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          if (canSubmit) submit();
        }}
      >
        <div className="flex flex-col gap-1">
          <label htmlFor="pair-address" className="text-xs text-(--color-text-secondary)">
            Server address
          </label>
          <input
            id="pair-address"
            value={address}
            onChange={(event) => {
              setAddress(event.target.value);
            }}
            placeholder="192.168.1.20"
            autoComplete="off"
            spellCheck={false}
            className="w-48 rounded border border-(--color-border-subtle) bg-(--color-surface) px-3 py-1.5 font-mono text-sm"
          />
        </div>

        <div className="flex flex-col gap-1">
          <label htmlFor="pair-name" className="text-xs text-(--color-text-secondary)">
            Name it
          </label>
          <input
            id="pair-name"
            value={name}
            onChange={(event) => {
              setName(event.target.value);
            }}
            placeholder="Home server"
            maxLength={64}
            className="w-40 rounded border border-(--color-border-subtle) bg-(--color-surface) px-3 py-1.5 text-sm"
          />
        </div>

        <div className="flex flex-col gap-1">
          <label htmlFor="pairing-code" className="text-xs text-(--color-text-secondary)">
            Pairing code
          </label>
          <input
            id="pairing-code"
            value={code}
            onChange={(event) => {
              setCode(event.target.value);
            }}
            placeholder="XXX-XXX-XXX"
            maxLength={16}
            autoComplete="off"
            spellCheck={false}
            aria-invalid={formatOk === false}
            aria-describedby="pairing-code-help"
            className="w-44 rounded border border-(--color-border-subtle) bg-(--color-surface) px-3 py-1.5 font-mono text-sm tracking-wider uppercase"
          />
        </div>

        <Button type="submit" variant="primary" disabled={!canSubmit}>
          {pairing ? 'Pairing…' : 'Pair'}
        </Button>
        {formatOk === true && <Badge tone="success">Valid format</Badge>}
        {formatOk === false && <Badge tone="danger">Not a valid code</Badge>}
      </form>

      <p id="pairing-code-help" className="mt-3 max-w-prose text-xs text-(--color-text-secondary)">
        Codes are nine characters and expire after three minutes. The characters
        <span className="font-mono"> 0 1 I L O U </span> are never used, so there is nothing to
        mistype. After pairing, compare the fingerprint shown here with the one printed on the
        server — that comparison is what confirms you paired with the machine you meant to.
      </p>
    </div>
  );
}

/**
 * Live connection status for the selected server.
 *
 * Shows the precise state rather than a spinner, because "reconnecting, attempt 3" and
 * "the server refused this device" call for completely different responses from the
 * operator.
 */
function ConnectionBanner({
  state,
  onDisconnect,
  onReconnect,
  busy,
}: {
  readonly state: ConnectionState;
  readonly onDisconnect: () => void;
  readonly onReconnect: () => void;
  readonly busy: boolean;
}): React.JSX.Element | null {
  if (state.state === 'offline') return null;

  const tone =
    state.state === 'refused' || state.state === 'failed'
      ? 'danger'
      : isConnected(state)
        ? 'success'
        : 'warning';

  const isAlert = state.state === 'refused' || state.state === 'failed';

  return (
    <div
      role={isAlert ? 'alert' : 'status'}
      className={`mb-6 rounded border p-4 ${
        isAlert ? 'border-(--color-danger)' : 'border-(--color-border-subtle)'
      }`}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Badge tone={tone}>{humanise(state.state)}</Badge>
          <span className="text-sm">{describeConnectionState(state)}</span>
        </div>
        <div className="flex gap-1.5">
          {isConnected(state) && (
            <Button variant="danger" onClick={onDisconnect} disabled={busy}>
              Disconnect
            </Button>
          )}
          {(state.state === 'failed' || state.state === 'refused') && (
            <Button onClick={onReconnect} disabled={busy || state.state === 'refused'}>
              Try again
            </Button>
          )}
        </div>
      </div>

      {state.state === 'refused' && state.reason === 'identity_changed' && (
        <p className="mt-2 max-w-prose text-xs text-(--color-danger)">
          This is the one failure worth stopping for. Either the server was reinstalled — in which
          case remove the saved entry and pair again — or something is impersonating it. The
          connection was refused; nothing was sent.
        </p>
      )}
    </div>
  );
}

/** One device row. */
function DeviceCard({
  device,
  connection,
  busy,
  onConnect,
  onDisconnect,
  renaming,
  draftName,
  onDraftName,
  onStartRename,
  onCancelRename,
  onCommitRename,
  onRevoke,
}: {
  readonly device: TrustedDevice;
  readonly connection: ConnectionState;
  readonly busy: boolean;
  readonly onConnect: () => void;
  readonly onDisconnect: () => void;
  readonly renaming: boolean;
  readonly draftName: string;
  readonly onDraftName: (name: string) => void;
  readonly onStartRename: () => void;
  readonly onCancelRename: () => void;
  readonly onCommitRename: () => void;
  readonly onRevoke: () => void;
}): React.JSX.Element {
  return (
    <li
      className={`rounded border p-4 ${
        device.revoked
          ? 'border-(--color-border-subtle) opacity-70'
          : 'border-(--color-border-subtle)'
      }`}
    >
      <div className="mb-2 flex flex-wrap items-start justify-between gap-2">
        <div>
          {renaming ? (
            <form
              onSubmit={(event) => {
                event.preventDefault();
                onCommitRename();
              }}
              className="flex items-center gap-2"
            >
              <label htmlFor={`rename-${device.deviceId}`} className="sr-only">
                New name
              </label>
              <input
                id={`rename-${device.deviceId}`}
                value={draftName}
                onChange={(event) => {
                  onDraftName(event.target.value);
                }}
                maxLength={128}
                autoFocus
                className="rounded border border-(--color-border-subtle) bg-(--color-surface) px-2 py-1 text-sm"
              />
              <Button type="submit" variant="primary">
                Save
              </Button>
              <Button variant="ghost" onClick={onCancelRename}>
                Cancel
              </Button>
            </form>
          ) : (
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium">{device.displayName}</span>
              <Badge tone={device.revoked ? 'danger' : 'success'}>
                {device.revoked ? 'Revoked' : 'Paired'}
              </Badge>
              <Badge>{ROLE_LABELS[device.role]}</Badge>
            </div>
          )}
          <p className="mt-0.5 text-xs text-(--color-text-secondary)">
            {device.hostname === '' ? 'Unknown host' : device.hostname}
          </p>
        </div>

        {!device.revoked && !renaming && (
          <div className="flex flex-wrap gap-1.5">
            {isConnected(connection) ? (
              <Button variant="danger" onClick={onDisconnect}>
                Disconnect
              </Button>
            ) : (
              <Button variant="primary" onClick={onConnect} disabled={busy || isBusy(connection)}>
                {busy ? 'Connecting…' : 'Connect'}
              </Button>
            )}
            <Button variant="ghost" onClick={onStartRename}>
              Rename
            </Button>
            <CopyButton value={device.identityFingerprint} label="fingerprint" />
            <Button variant="danger" onClick={onRevoke}>
              Revoke
            </Button>
          </div>
        )}
      </div>

      <dl className="grid gap-x-6 gap-y-0.5 text-xs sm:grid-cols-[max-content_1fr]">
        <dt className="text-(--color-text-secondary)">Device ID</dt>
        <dd className="font-mono break-all">{device.deviceId}</dd>

        <dt className="text-(--color-text-secondary)">Identity fingerprint</dt>
        <dd
          className="font-mono break-all"
          title={formatFingerprintGroups(device.identityFingerprint)}
        >
          {abbreviateFingerprint(device.identityFingerprint)}
        </dd>

        <dt className="text-(--color-text-secondary)">First paired</dt>
        <dd>{formatTimestamp(device.pairedAtMs)}</dd>

        <dt className="text-(--color-text-secondary)">Last authenticated</dt>
        <dd>
          {device.lastAuthenticatedAtMs === null
            ? 'Never connected'
            : `${formatRelative(device.lastAuthenticatedAtMs)} · ${formatTimestamp(device.lastAuthenticatedAtMs)}`}
        </dd>

        {device.revoked && (
          <>
            <dt className="text-(--color-text-secondary)">Revoked</dt>
            <dd>{formatTimestamp(device.revokedAtMs)}</dd>
          </>
        )}

        <dt className="text-(--color-text-secondary)">Permissions</dt>
        <dd>
          {device.capabilities.length === 0
            ? 'None'
            : device.capabilities.map((c) => humanise(c)).join(', ')}
        </dd>
      </dl>
    </li>
  );
}
