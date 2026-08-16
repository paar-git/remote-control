/**
 * Settings as a page of sections, not more navigation.
 *
 * Only controls this build can honour. Start with system, start minimized and minimize
 * to tray have no implementation, so they are absent.
 */

import { useCallback, useEffect, useState } from 'react';

import {
  getClientInfo,
  getHostSettings,
  getHostStatus,
  probeDevice,
  setAccepting,
  setUnattendedPassword,
  type HostStatus,
  type Permission,
  type Settings,
} from './api.js';
import { RcMark } from './chrome';
import { GRANTABLE_PERMISSIONS } from './labels.js';
import {
  loadPreferences,
  resetPreferences,
  savePreferences,
  type DisplayPreferences,
} from './displays';
import { applyTheme, loadTheme, saveTheme, type ThemePreference } from './theme.js';
import { Button, TextField, Toggle, type Toast } from './ui';
import UpdatesPane from './UpdatesPane';

const MIN_PASSWORD_LENGTH = 12;

export function SettingsPage({
  onToast,
  onViewDevices,
  hostEpoch = 0,
}: {
  readonly onToast: (toast: Toast) => void;
  readonly onViewDevices: () => void;
  readonly hostEpoch?: number | undefined;
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
  const [displays, setDisplays] = useState<DisplayPreferences>(loadPreferences);
  const [probeResult, setProbeResult] = useState<string | null>(null);
  const [probing, setProbing] = useState(false);
  const [appVersion, setAppVersion] = useState<string | null>(null);

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
    getClientInfo()
      .then((info) => {
        setAppVersion(info.appVersion);
      })
      .catch(() => undefined);
  }, [hostEpoch]);

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
    <div className="w-full max-w-[760px]">
      <SettingsSection title="Remote Access">
        {settings !== null && (
          <div className="mb-4 flex items-start justify-between gap-6">
            <div className="min-w-0">
              <p className="text-sm">Allow incoming connections</p>
              <p className="mt-0.5 text-[13px] text-(--color-text-secondary)">
                Other machines can reach this one only while this is on.
              </p>
            </div>
            <Toggle
              label="Allow incoming connections"
              checked={status?.accepting ?? settings.accepting}
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
          <legend className="mb-2 text-[13px] font-medium text-(--color-text-secondary)">
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
      </SettingsSection>

      <SettingsSection title="Security">
        <div className="flex items-start justify-between gap-6">
          <div className="min-w-0">
            <p className="text-sm">Trusted devices</p>
            <p className="mt-0.5 text-[13px] text-(--color-text-secondary)">
              Administrator is never granted from the Accept dialog. It is granted only from My
              Devices, after a confirmation that names the device and the privileges.
            </p>
          </div>
          <Button variant="default" onClick={onViewDevices}>
            Manage trusted devices
          </Button>
        </div>
      </SettingsSection>

      <SettingsSection title="Network">
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
        <div className="mt-5">
          <UpdatesPane onToast={onToast} />
        </div>
      </SettingsSection>

      <SettingsSection title="Multi-display">
        <div className="flex items-start justify-between gap-6">
          <div className="min-w-0">
            <p className="text-sm">Moving between displays</p>
            <p className="mt-0.5 text-[13px] text-(--color-text-secondary)">
              What happens when the pointer reaches the edge of a remote display and
              another one is beyond it.
            </p>
          </div>
          <fieldset>
            <legend className="sr-only">Moving between displays</legend>
            <div className="inline-flex rounded-[4px] border border-(--color-border) bg-(--color-page) p-0.5">
              {(
                [
                  ['ask', 'Ask'],
                  ['automatic', 'Switch'],
                  ['never', 'Never'],
                ] as const
              ).map(([value, label]) => (
                <button
                  key={value}
                  type="button"
                  role="radio"
                  aria-checked={displays.switchMode === value}
                  className={
                    'rounded-[3px] px-3 py-1.5 text-sm font-medium transition-colors ' +
                    (displays.switchMode === value
                      ? 'bg-(--color-card) text-(--color-text)'
                      : 'text-(--color-text-secondary) hover:text-(--color-text)')
                  }
                  onClick={() => {
                    const next: DisplayPreferences = {
                      ...displays,
                      switchMode: value,
                    };
                    setDisplays(next);
                    savePreferences(next);
                  }}
                >
                  {label}
                </button>
              ))}
            </div>
          </fieldset>
        </div>

        <div className="mt-4 flex items-start justify-between gap-6">
          <div className="min-w-0">
            <p className="text-sm">Saved choice</p>
            <p className="mt-0.5 text-[13px] text-(--color-text-secondary)">
              {displays.switchMode === 'ask'
                ? 'Nothing saved: you will be asked the first time you reach an edge.'
                : 'Clearing this makes the session ask again the next time you reach an edge.'}
            </p>
          </div>
          <Button
            variant="default"
            disabled={displays.switchMode === 'ask'}
            onClick={() => {
              setDisplays(resetPreferences());
              onToast({ kind: 'success', message: 'Display switching will ask again.' });
            }}
          >
            Reset
          </Button>
        </div>
      </SettingsSection>

      <SettingsSection title="Appearance">
        <div className="flex items-start justify-between gap-6">
          <div className="min-w-0">
            <p className="text-sm">Theme</p>
            <p className="mt-0.5 text-[13px] text-(--color-text-secondary)">
              Dark is the default. Light and system follow this window.
            </p>
          </div>
          <fieldset>
          <legend className="sr-only">Theme</legend>
          <div className="inline-flex rounded-[4px] border border-(--color-border) bg-(--color-page) p-0.5">
            {(
              [
                ['light', 'Light'],
                ['dark', 'Dark'],
                ['system', 'System'],
              ] as const
            ).map(([value, label]) => (
              <button
                key={value}
                type="button"
                role="radio"
                aria-checked={theme === value}
                className={
                  'rounded-[3px] px-3 py-1.5 text-sm font-medium transition-colors ' +
                  (theme === value
                    ? 'bg-(--color-card) text-(--color-text)'
                    : 'text-(--color-text-secondary) hover:text-(--color-text)')
                }
                onClick={() => {
                  changeTheme(value);
                }}
              >
                {label}
              </button>
            ))}
          </div>
        </fieldset>
        </div>
      </SettingsSection>

      <SettingsSection title="About" last>
        <div className="flex items-center gap-2.5">
          <RcMark size={21} />
          <div>
            <p className="text-[15px] leading-none font-semibold tracking-[-0.03em]">RC</p>
            <p className="mt-1.5 text-[13px] text-(--color-text-secondary)">
              Version {appVersion ?? '—'}
            </p>
          </div>
        </div>
      </SettingsSection>
    </div>
  );
}

function SettingsSection({
  title,
  last = false,
  children,
}: {
  readonly title: string;
  readonly last?: boolean | undefined;
  readonly children: React.ReactNode;
}): React.JSX.Element {
  return (
    <section className={last ? 'py-4' : 'border-b border-(--color-border) py-4'}>
      <h2 className="mb-3 text-[17px] font-medium">{title}</h2>
      {children}
    </section>
  );
}
