/**
 * Everything that is not a session.
 *
 * Four sections, one dialog. The old build had eleven sidebar sections; almost all of
 * them were settings, and settings are something you visit rarely and leave.
 *
 * # A control shows the machine's state, never the user's intent
 *
 * Every switch here reflects what the backend last confirmed. A save that fails puts
 * the control back — because a switch left in the position the user moved it to would
 * say unattended access was on when the machine had refused to turn it on, which is the
 * one direction that must never be wrong.
 *
 * The failure is reported *outside* the section the switch reveals. Putting it in the
 * password field would mean reverting the switch unmounted the only explanation of why
 * it reverted, leaving a control that flips back on its own for no stated reason.
 *
 * # The password
 *
 * Held in component state, sent once, and cleared. It is typed into a `type="password"`
 * field whose value is never written to a DOM attribute, and the backend hashes it and
 * drops the plaintext. Nothing here can read back what was set: `unattendedConfigured`
 * says only that something exists.
 */

import { Info, Lock, Monitor, RefreshCw, X } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';

import {
  getClientInfo,
  getHostSettings,
  getLocalIdentity,
  setUnattendedPassword,
  type ClientInfo,
  type LocalIdentity,
  type Permission,
  type Settings,
} from './api.js';
import { formatFingerprintGroups } from './format.js';
import { Button, Card, CardHeader, TextField, type Toast } from './ui';
import UpdatesPane from './UpdatesPane';

/** The floor `rc-security` enforces. Stated here so the user is told before a round trip. */
const MIN_PASSWORD_LENGTH = 12;

/** What each permission is called, in words about what the other person can do. */
const PERMISSIONS: readonly { readonly id: Permission; readonly label: string }[] = [
  { id: 'control_input', label: 'Control keyboard and mouse' },
  { id: 'transfer_files', label: 'Transfer files' },
  { id: 'view_metrics', label: 'View system information' },
];

export function SettingsDialog({
  onClose,
  onToast,
}: {
  readonly onClose: () => void;
  readonly onToast: (toast: Toast) => void;
}): React.JSX.Element {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [identity, setIdentity] = useState<LocalIdentity | null>(null);
  const [info, setInfo] = useState<ClientInfo | null>(null);

  const [unattendedOn, setUnattendedOn] = useState(false);
  const [password, setPassword] = useState('');
  const [granted, setGranted] = useState<readonly Permission[]>(
    PERMISSIONS.map((permission) => permission.id),
  );
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    let cancelled = false;

    getHostSettings()
      .then((loaded) => {
        if (cancelled) return;
        setSettings(loaded);
        setUnattendedOn(loaded.unattendedConfigured);
        if (loaded.unattendedPermissions.length > 0) {
          setGranted(loaded.unattendedPermissions);
        }
      })
      .catch(() => {
        // The sections render their loading state. Claiming "off" for a setting that
        // could not be read would be a specific answer nobody gave.
      });

    getLocalIdentity()
      .then((loaded) => {
        if (!cancelled) setIdentity(loaded);
      })
      .catch(() => undefined);

    getClientInfo()
      .then((loaded) => {
        if (!cancelled) setInfo(loaded);
      })
      .catch(() => undefined);

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const onKey = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('keydown', onKey);
    };
  }, [onClose]);

  const savePassword = useCallback(() => {
    if (password.length < MIN_PASSWORD_LENGTH) {
      setError(`Use a password of at least ${MIN_PASSWORD_LENGTH} characters.`);
      return;
    }
    if (granted.length === 0) {
      setError('Choose at least one thing an unattended connection may do.');
      return;
    }

    setSaving(true);
    setError(null);
    setUnattendedPassword(password, [...granted])
      .then(() => {
        // Dropped as soon as it has been sent. Nothing reads it back.
        setPassword('');
        setSettings((current) =>
          current === null ? current : { ...current, unattendedConfigured: true },
        );
        onToast({ kind: 'success', message: 'Unattended access is on.' });
      })
      .catch((error_: unknown) => {
        setError(error_ instanceof Error ? error_.message : 'That could not be saved.');
        // Back to what the machine actually holds, not what was attempted.
        setUnattendedOn(settings?.unattendedConfigured ?? false);
      })
      .finally(() => {
        setSaving(false);
      });
  }, [password, granted, onToast, settings]);

  const turnOff = useCallback(() => {
    setSaving(true);
    setError(null);
    setUnattendedPassword(null, [])
      .then(() => {
        setPassword('');
        setSettings((current) =>
          current === null ? current : { ...current, unattendedConfigured: false },
        );
      })
      .catch((error_: unknown) => {
        setError(error_ instanceof Error ? error_.message : 'That could not be saved.');
        setUnattendedOn(settings?.unattendedConfigured ?? false);
      })
      .finally(() => {
        setSaving(false);
      });
  }, [settings]);

  return (
    <div className="fixed inset-0 z-40 flex items-start justify-center overflow-y-auto bg-black/55 p-6">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="settings-title"
        className="w-full max-w-2xl rounded-xl border border-(--color-border) bg-(--color-page) shadow-lg"
      >
        <header className="flex items-center gap-3 border-b border-(--color-border) px-5 py-3">
          <h2 id="settings-title" className="min-w-0 flex-1 text-base font-semibold">
            Settings
          </h2>
          <Button icon={X} variant="ghost" size="sm" onClick={onClose}>
            Close
          </Button>
        </header>

        <div className="flex flex-col gap-4 p-5">
          <Card>
            <CardHeader icon={Monitor} title="This computer" />
            {settings === null ? (
              <p className="text-sm text-(--color-text-secondary)">Reading settings…</p>
            ) : (
              <dl className="flex flex-col gap-2 text-sm">
                <Row label="Name" value={settings.machineName} />
                <Row label="Port" value={String(settings.listenPort)} mono />
              </dl>
            )}
          </Card>

          <Card>
            <CardHeader icon={Lock} title="Incoming connections" />

            <label className="flex items-start gap-2.5 text-sm">
              <input
                type="checkbox"
                className="mt-0.5 size-4 accent-(--color-accent)"
                checked={unattendedOn}
                disabled={saving || settings === null}
                onChange={(event) => {
                  setUnattendedOn(event.target.checked);
                  setError(null);
                  // Turning it off takes effect immediately: withdrawing access should
                  // never wait for a second confirming click. Turning it on needs a
                  // password, so it waits for Save.
                  if (!event.target.checked) turnOff();
                }}
              />
              <span>
                <span className="block font-medium">Unattended access</span>
                <span className="block text-(--color-text-secondary)">
                  Let someone in with a password instead of asking you each time.
                </span>
              </span>
            </label>

            {error !== null && (
              <p
                role="alert"
                data-testid="unattended-error"
                className="mt-2 text-sm text-(--color-danger)"
              >
                {error}
              </p>
            )}

            {unattendedOn && (
              <div className="mt-3 flex flex-col gap-3 border-t border-(--color-border) pt-3">
                <TextField
                  label="Password"
                  type="password"
                  value={password}
                  onChange={(value) => {
                    setPassword(value);
                    setError(null);
                  }}
                  autoComplete="new-password"
                  help={
                    settings?.unattendedConfigured === true
                      ? 'A password is already set. Entering one here replaces it.'
                      : `At least ${MIN_PASSWORD_LENGTH} characters.`
                  }
                />

                <fieldset>
                  <legend className="mb-2 text-xs font-medium text-(--color-text-secondary)">
                    An unattended connection may
                  </legend>
                  <div className="flex flex-col gap-1.5">
                    {PERMISSIONS.map((permission) => (
                      <label key={permission.id} className="flex items-center gap-2.5 text-sm">
                        <input
                          type="checkbox"
                          className="size-4 accent-(--color-accent)"
                          checked={granted.includes(permission.id)}
                          onChange={(event) => {
                            setGranted((current) =>
                              event.target.checked
                                ? [...current, permission.id]
                                : current.filter((id) => id !== permission.id),
                            );
                          }}
                        />
                        {permission.label}
                      </label>
                    ))}
                  </div>
                </fieldset>

                <Button variant="primary" disabled={saving} onClick={savePassword}>
                  Save password
                </Button>
              </div>
            )}
          </Card>

          <Card>
            <CardHeader icon={RefreshCw} title="Updates" />
            <UpdatesPane onToast={onToast} />
          </Card>

          <Card>
            <CardHeader icon={Info} title="About" />
            <dl className="flex flex-col gap-2 text-sm">
              <Row label="Version" value={info?.appVersion ?? '—'} />
              <div className="flex gap-2">
                <dt className="w-28 shrink-0 text-(--color-text-secondary)">Identity</dt>
                <dd
                  data-testid="about-fingerprint"
                  className="min-w-0 flex-1 font-mono text-xs leading-relaxed break-all"
                >
                  {identity === null ? '—' : formatFingerprintGroups(identity.identityFingerprint)}
                </dd>
              </div>
            </dl>
          </Card>
        </div>
      </div>
    </div>
  );
}

/** One label-and-value row. */
function Row({
  label,
  value,
  mono = false,
}: {
  readonly label: string;
  readonly value: string;
  readonly mono?: boolean | undefined;
}): React.JSX.Element {
  return (
    <div className="flex gap-2">
      <dt className="w-28 shrink-0 text-(--color-text-secondary)">{label}</dt>
      <dd className={`min-w-0 flex-1 truncate ${mono ? 'font-mono text-xs' : ''}`}>{value}</dd>
    </div>
  );
}
