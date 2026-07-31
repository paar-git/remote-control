/**
 * The Devices screen.
 *
 * Everything shown here is real, persisted state read through validated commands.
 * The one thing that is *not* available yet is completing a pairing exchange, which
 * needs the network transport from phase 3 — the pairing panel says so plainly rather
 * than presenting a button that would do nothing.
 */

import { useCallback, useEffect, useState } from 'react';

import {
  ROLE_LABELS,
  type LocalIdentity,
  type TrustedDevice,
  checkPairingCodeFormat,
  getLocalIdentity,
  listTrustedDevices,
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

      {identity !== null && <ThisDevice identity={identity} />}

      <PairingPanel />

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
 * The pairing entry panel.
 *
 * The code field is real and validates format against the backend as you type. The
 * exchange itself cannot run until the transport lands, and the panel says so.
 */
function PairingPanel(): React.JSX.Element {
  const [code, setCode] = useState('');
  const [formatOk, setFormatOk] = useState<boolean | null>(null);

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

  return (
    <div className="rounded border border-(--color-border-subtle) p-4">
      <h3 className="mb-1 text-sm font-semibold">Pair a new server</h3>
      <p className="mb-3 max-w-prose text-sm text-(--color-text-secondary)">
        Run <code className="font-mono text-xs">rc-agent pair</code> on the server to display a
        code, then enter it here.
      </p>

      <div className="flex flex-wrap items-center gap-2">
        <label htmlFor="pairing-code" className="sr-only">
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
        <Button
          variant="primary"
          disabled
          title="Pairing needs the network transport, which arrives in phase 3"
        >
          Pair
        </Button>
        {formatOk === true && <Badge tone="success">Valid format</Badge>}
        {formatOk === false && <Badge tone="danger">Not a valid code</Badge>}
      </div>

      <p id="pairing-code-help" className="mt-3 max-w-prose text-xs text-(--color-text-secondary)">
        Codes are nine characters and expire after three minutes. The characters
        <span className="font-mono"> 0 1 I L O U </span> are never used, so there is nothing to
        mistype. Completing a pairing requires the network transport, which arrives in phase 3; the
        field above checks the format only.
      </p>
    </div>
  );
}

/** One device row. */
function DeviceCard({
  device,
  renaming,
  draftName,
  onDraftName,
  onStartRename,
  onCancelRename,
  onCommitRename,
  onRevoke,
}: {
  readonly device: TrustedDevice;
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
            <Button
              disabled
              title="Connecting needs the network transport, which arrives in phase 3"
            >
              Connect
            </Button>
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
