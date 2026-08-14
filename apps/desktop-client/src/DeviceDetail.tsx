/**
 * Access, permissions and security for one trusted device.
 *
 * Unattended access and permissions are separate sections because they are separate
 * decisions. Administrator is a second confirmation, never a switch that takes effect
 * on the click that opened it.
 */

import { useState } from 'react';

import {
  revokeDevice,
  setDevicePermissions,
  setDeviceSuspended,
  setDeviceUnattended,
  type Presence,
  type TrustedDevice,
} from './api.js';
import {
  formatDeviceId,
  formatFingerprintGroups,
  formatRelative,
  formatTimestamp,
} from './format.js';
import { GrantAdminDialog } from './GrantAdminDialog';
import { GRANTABLE_PERMISSIONS, osLabel } from './labels.js';
import { Button, ConfirmDialog, Toggle, type Toast } from './ui';

export function DeviceDetail({
  device,
  presence,
  onChanged,
  onClose,
  onToast,
}: {
  readonly device: TrustedDevice;
  readonly presence: Presence;
  readonly onChanged: () => void;
  readonly onClose: () => void;
  readonly onToast: (toast: Toast) => void;
}): React.JSX.Element {
  const [grantOpen, setGrantOpen] = useState(false);
  const [revokeOpen, setRevokeOpen] = useState(false);
  const [adminInfoOpen, setAdminInfoOpen] = useState(false);
  const [busy, setBusy] = useState(false);

  const isAdmin = device.permissions.includes('administer');

  const fail = (error: unknown): void => {
    onToast({
      kind: 'error',
      message: error instanceof Error ? error.message : 'That change could not be saved.',
    });
    setBusy(false);
  };

  const after = (): void => {
    setBusy(false);
    onChanged();
  };

  const toggleUnattended = (next: boolean): void => {
    setBusy(true);
    setDeviceUnattended(device.identityFingerprint, next).then(after, fail);
  };

  const togglePermission = (
    id: (typeof GRANTABLE_PERMISSIONS)[number]['id'],
    next: boolean,
  ): void => {
    const nextSet = next
      ? [...device.permissions, id]
      : device.permissions.filter((permission) => permission !== id);
    setBusy(true);
    setDevicePermissions(device.identityFingerprint, nextSet).then(after, fail);
  };

  const toggleAdmin = (next: boolean): void => {
    if (next) {
      setGrantOpen(true);
      return;
    }
    setBusy(true);
    setDevicePermissions(
      device.identityFingerprint,
      device.permissions.filter((permission) => permission !== 'administer'),
    ).then(after, fail);
  };

  const confirmAdmin = (): void => {
    const next = device.permissions.includes('administer')
      ? device.permissions
      : [...device.permissions, 'administer' as const];
    setGrantOpen(false);
    setBusy(true);
    setDevicePermissions(device.identityFingerprint, next).then(after, fail);
  };

  const toggleSuspended = (next: boolean): void => {
    setBusy(true);
    setDeviceSuspended(device.identityFingerprint, next).then(after, fail);
  };

  const confirmRevoke = (): void => {
    setRevokeOpen(false);
    setBusy(true);
    revokeDevice(device.identityFingerprint).then(() => {
      setBusy(false);
      onChanged();
      onClose();
    }, fail);
  };

  return (
    <div className="fixed inset-0 z-40 flex items-start justify-center overflow-y-auto bg-black/55 p-6">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="device-detail-title"
        className="w-full max-w-lg rounded-xl border border-(--color-border) bg-(--color-page) p-5 shadow-lg"
      >
        <header className="mb-5 flex items-start justify-between gap-3">
          <div>
            <h2 id="device-detail-title" className="text-lg font-semibold">
              {device.displayName}
            </h2>
            <p className="text-sm text-(--color-text-secondary)">
              {osLabel(device.osFamily)}
              {presence === 'online' ? ' · Online' : presence === 'offline' ? ' · Offline' : ''}
            </p>
            <p className="mt-1 font-mono text-xs text-(--color-text-secondary)">
              {formatDeviceId(device.identityFingerprint)}
            </p>
          </div>
          <Button variant="ghost" size="sm" onClick={onClose}>
            Close
          </Button>
        </header>

        <section className="mb-5">
          <h3 className="mb-3 text-sm font-semibold">Access</h3>
          <div className="mb-3 flex items-center justify-between gap-3">
            <div>
              <p className="text-sm font-medium">Trusted device</p>
              <p className="text-xs text-(--color-text-secondary)">
                Remembered. Revoking is how this is turned off.
              </p>
            </div>
            <p className="text-sm font-medium text-(--color-text-secondary)">Enabled</p>
          </div>
          <div className="flex items-center justify-between gap-3">
            <div>
              <p className="text-sm font-medium">Connect without approval</p>
              <p className="text-xs text-(--color-text-secondary)">
                This device may reconnect while nobody is at the keyboard.
              </p>
            </div>
            <Toggle
              label="Connect without approval"
              checked={device.unattended}
              disabled={busy}
              onChange={toggleUnattended}
            />
          </div>
        </section>

        <section className="mb-5" data-testid="permissions-section">
          <h3 className="mb-3 text-sm font-semibold">Permissions</h3>
          <div className="flex flex-col gap-3">
            {GRANTABLE_PERMISSIONS.map((permission) => (
              <div key={permission.id} className="flex items-center justify-between gap-3">
                <p className="text-sm">{permission.label}</p>
                <Toggle
                  label={permission.label}
                  checked={device.permissions.includes(permission.id)}
                  disabled={busy}
                  onChange={(next) => {
                    togglePermission(permission.id, next);
                  }}
                />
              </div>
            ))}
          </div>
        </section>

        <section className="mb-5">
          <h3 className="mb-3 text-sm font-semibold">Security</h3>
          <div className="mb-4 flex items-center justify-between gap-3">
            <div>
              <p className="text-sm font-medium">Administrator Access</p>
              <p className="text-xs text-(--color-text-secondary)">
                Lets this device manage the machines you trust.
              </p>
            </div>
            <Toggle
              label="Administrator Access"
              checked={isAdmin}
              disabled={busy}
              onChange={toggleAdmin}
            />
          </div>
          {isAdmin && (
            <Button variant="ghost" size="sm" onClick={() => setAdminInfoOpen(true)}>
              Admin access
            </Button>
          )}
          <div className="mt-4 flex items-center justify-between gap-3">
            <div>
              <p className="text-sm font-medium">Temporarily disable</p>
              <p className="text-xs text-(--color-text-secondary)">
                Refuse this device without forgetting it.
              </p>
            </div>
            <Toggle
              label="Temporarily disable"
              checked={device.suspended}
              disabled={busy}
              onChange={toggleSuspended}
            />
          </div>
          <p className="mt-4 text-sm">Device identity verified</p>
          <p className="font-mono text-xs break-all text-(--color-text-secondary)">
            {formatFingerprintGroups(device.identityFingerprint)}
          </p>
          <p className="mt-2 text-xs text-(--color-text-secondary)">
            Added {formatTimestamp(device.addedMs)}
          </p>
          <p className="text-xs text-(--color-text-secondary)">
            Last connection {formatRelative(device.lastConnectedMs)}
          </p>
          <div className="mt-4">
            <Button
              variant="danger"
              disabled={busy}
              onClick={() => {
                setRevokeOpen(true);
              }}
            >
              Revoke Access
            </Button>
          </div>
        </section>
      </div>

      {grantOpen && (
        <GrantAdminDialog
          device={device}
          onCancel={() => {
            setGrantOpen(false);
          }}
          onConfirm={confirmAdmin}
        />
      )}

      <ConfirmDialog
        open={revokeOpen}
        title="Revoke Access"
        body={`${device.displayName} will have to be accepted again the next time it connects.`}
        confirmLabel="Revoke"
        destructive
        onCancel={() => {
          setRevokeOpen(false);
        }}
        onConfirm={confirmRevoke}
      />

      {adminInfoOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-[rgb(16_24_40_/_40%)] p-4">
          <div
            role="dialog"
            aria-modal="true"
            aria-label="Administrator access"
            className="w-full max-w-sm rounded-xl border border-(--color-border) bg-(--color-card) p-5"
          >
            <p className="text-sm">
              Administrator access lets {device.displayName} manage this machine’s trusted devices:
              list them, change what they may do, and revoke them.
            </p>
            <div className="mt-4 flex justify-end">
              <Button
                variant="default"
                onClick={() => {
                  setAdminInfoOpen(false);
                }}
              >
                Close
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
