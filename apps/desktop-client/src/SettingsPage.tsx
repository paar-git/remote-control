/**
 * Settings as a page of sections, not more navigation.
 *
 * Only controls this build can honour. Start with system, start minimized and minimize
 * to tray have no implementation, so they are absent.
 */

import { useCallback, useEffect, useState } from 'react';

import {
  getHostSettings,
  getHostStatus,
  probeDevice,
  setAccepting,
  setUnattendedPassword,
  type HostStatus,
  type Permission,
  type Settings,
} from './api.js';
import { GRANTABLE_PERMISSIONS } from './labels.js';
import { applyTheme, loadTheme, saveTheme, type ThemePreference } from './theme.js';
import { Button, Card, TextField, Toggle, type Toast } from './ui';
import UpdatesPane from './UpdatesPane';

const MIN_PASSWORD_LENGTH = 12;

export function SettingsPage({
  onToast,
  onViewDevices,
}: {
  readonly onToast: (toast: Toast) => void;
  readonly onViewDevices: () => void;
}): React.JSX.Element {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [status, setStatus] = useState<HostStatus | null>(null);
  const [password, setPassword] = useState('');
  const [granted, setGranted] = useState<readonly Permission[]>(
    GRANTABLE_PERMISSIONS.map((permission) => permission.id),
  );
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [theme, setTheme] = useState<ThemePreference>(loadTheme);
  const [probeResult, setProbeResult] = useState<string | null>(null);
  const [probing, setProbing] = useState(false);

  useEffect(() => {
    getHostSettings()
      .then((loaded) => {
        setSettings(loaded);
        if (loaded.unattendedPermissions.length > 0) {
          setGranted(loaded.unattendedPermissions.filter((item) => item !== 'administer'));
        }
      })
      .catch(() => undefined);
    getHostStatus()
      .then(setStatus)
      .catch(() => undefined);
  }, []);

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
        setPassword('');
        setSettings((current) =>
          current === null ? current : { ...current, unattendedConfigured: true },
        );
        onToast({ kind: 'success', message: 'Unattended access is on.' });
      })
      .catch((error_: unknown) => {
        setError(error_ instanceof Error ? error_.message : 'That could not be saved.');
      })
      .finally(() => {
        setSaving(false);
      });
  }, [password, granted, onToast]);

  const toggleAccepting = (next: boolean): void => {
    setAccepting(next)
      .then((updated) => {
        setStatus(updated);
        setSettings((current) =>
          current === null ? current : { ...current, accepting: updated.accepting },
        );
      })
      .catch((error_: unknown) => {
        onToast({
          kind: 'error',
          message:
            error_ instanceof Error ? error_.message : 'Could not change incoming connections.',
        });
      });
  };

  const changeTheme = (next: ThemePreference): void => {
    setTheme(next);
    saveTheme(next);
    applyTheme(next);
  };

  const runProbe = (): void => {
    const address = status?.addresses[0];
    if (address === undefined) return;
    setProbing(true);
    setProbeResult(null);
    probeDevice(address)
      .then((result) => {
        setProbeResult(result === 'online' ? 'This machine answered.' : 'Nothing answered.');
      })
      .catch((error_: unknown) => {
        setProbeResult(error_ instanceof Error ? error_.message : 'The probe failed.');
      })
      .finally(() => {
        setProbing(false);
      });
  };

  return (
    <div className="mx-auto flex w-full max-w-2xl flex-col gap-5">
      <Card>
        <h2 className="mb-4 text-xl font-semibold tracking-tight">Remote Access</h2>
        {settings !== null && (
          <div className="mb-4 flex items-center justify-between gap-3">
            <div>
              <p className="text-sm font-medium">Allow incoming connections</p>
              <p className="text-xs text-(--color-text-secondary)">
                Other machines can reach this one only while this is on.
              </p>
            </div>
            <Toggle
              label="Allow incoming connections"
              checked={settings.accepting}
              onChange={toggleAccepting}
            />
          </div>
        )}
        <TextField
          label="Unattended password"
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
        <fieldset className="mt-3">
          <legend className="mb-2 text-xs font-medium text-(--color-text-secondary)">
            An unattended connection may
          </legend>
          <div className="flex flex-col gap-1.5">
            {GRANTABLE_PERMISSIONS.map((permission) => (
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
        {error !== null && (
          <p role="alert" className="mt-2 text-sm text-(--color-danger)">
            {error}
          </p>
        )}
        <div className="mt-3">
          <Button variant="primary" disabled={saving} onClick={savePassword}>
            Save password
          </Button>
        </div>
      </Card>

      <Card>
        <h2 className="mb-3 text-xl font-semibold tracking-tight">Security</h2>
        <p className="mb-3 text-sm text-(--color-text-secondary)">
          Administrator is never granted from the Accept dialog. It is granted only from My Devices,
          after a confirmation that names the device and the privileges.
        </p>
        <Button variant="default" onClick={onViewDevices}>
          Manage trusted devices
        </Button>
      </Card>

      <Card>
        <h2 className="mb-4 text-xl font-semibold tracking-tight">Network</h2>
        <dl className="mb-4 flex flex-col gap-2 text-sm">
          <div className="flex gap-3">
            <dt className="w-28 shrink-0 text-(--color-text-secondary)">Listen port</dt>
            <dd className="font-mono">{status?.listenPort ?? settings?.listenPort ?? '—'}</dd>
          </div>
          {(status?.addresses ?? []).map((address) => (
            <div key={address} className="flex gap-3">
              <dt className="w-28 shrink-0 text-(--color-text-secondary)">Address</dt>
              <dd className="min-w-0 flex-1 font-mono text-xs break-all">{address}</dd>
            </div>
          ))}
        </dl>
        <Button variant="default" disabled={probing || status === null} onClick={runProbe}>
          Check this machine
        </Button>
        {probeResult !== null && (
          <p role="status" className="mt-2 text-sm text-(--color-text-secondary)">
            {probeResult}
          </p>
        )}
        <div className="mt-5 border-t border-(--color-border) pt-4">
          <UpdatesPane onToast={onToast} />
        </div>
      </Card>

      <Card>
        <h2 className="mb-3 text-xl font-semibold tracking-tight">Appearance</h2>
        <fieldset>
          <legend className="mb-2 text-sm text-(--color-text-secondary)">Theme</legend>
          <div className="flex flex-wrap gap-3">
            {(
              [
                ['light', 'Light'],
                ['dark', 'Dark'],
                ['system', 'System'],
              ] as const
            ).map(([value, label]) => (
              <label key={value} className="flex items-center gap-2 text-sm">
                <input
                  type="radio"
                  name="theme"
                  value={value}
                  checked={theme === value}
                  onChange={() => {
                    changeTheme(value);
                  }}
                />
                {label}
              </label>
            ))}
          </div>
        </fieldset>
      </Card>
    </div>
  );
}
