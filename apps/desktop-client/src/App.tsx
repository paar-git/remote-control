/**
 * Application shell.
 *
 * The app is gated: on first run it asks for an owner account, thereafter it asks for
 * the owner password. Only once unlocked does the sidebar appear. Sections whose
 * features arrive in a later phase are rendered disabled and labelled with the phase,
 * rather than as buttons that look live and do nothing.
 */

import { useCallback, useEffect, useState } from 'react';

import {
  type ClientInfo,
  type OwnerStatus,
  createOwner,
  getClientInfo,
  getOwnerStatus,
  ownerLogin,
  ownerLogout,
} from './api.js';
import { Button, type Toast, ToastBar } from './components';
import DevicesScreen from './DevicesScreen';
import FilesScreen from './FilesScreen';
import MonitoringScreen from './MonitoringScreen';
import TerminalScreen from './TerminalScreen';
import UpdateScreen from './UpdateScreen';
import { isTauriAvailable } from './ipc.js';
import { isReadyToInstall, pendingUpdateVersion } from './updates.js';
import { useUpdateWatcher } from './useUpdateWatcher.js';

interface NavItem {
  readonly id: string;
  readonly label: string;
  /** `null` once the section is implemented. */
  readonly availableInPhase: number | null;
}

const NAV_ITEMS: readonly NavItem[] = [
  { id: 'home', label: 'Home', availableInPhase: null },
  { id: 'devices', label: 'Devices', availableInPhase: null },
  { id: 'remote-desktop', label: 'Remote Desktop', availableInPhase: 6 },
  { id: 'terminal', label: 'Terminal', availableInPhase: null },
  { id: 'files', label: 'Files', availableInPhase: null },
  { id: 'processes', label: 'Processes', availableInPhase: 7 },
  { id: 'services', label: 'Services', availableInPhase: 7 },
  { id: 'monitoring', label: 'Monitoring', availableInPhase: null },
  { id: 'updates', label: 'Updates', availableInPhase: null },
  { id: 'power', label: 'Power', availableInPhase: 7 },
  { id: 'activity', label: 'Activity', availableInPhase: 7 },
  { id: 'settings', label: 'Settings', availableInPhase: 9 },
];

type Gate =
  | { readonly status: 'loading' }
  | { readonly status: 'unavailable'; readonly message: string }
  | { readonly status: 'setup' }
  | { readonly status: 'locked' }
  | { readonly status: 'unlocked'; readonly username: string };

export default function App(): React.JSX.Element {
  const [gate, setGate] = useState<Gate>({ status: 'loading' });
  const [section, setSection] = useState('home');
  const [toast, setToast] = useState<Toast | null>(null);
  // Only poll for releases once the app is unlocked; before that the backend
  // refuses the capability check anyway.
  const updates = useUpdateWatcher(gate.status === 'unlocked');
  const pendingVersion = pendingUpdateVersion(updates.status);

  const applyStatus = useCallback((status: OwnerStatus) => {
    if (status.authenticated && status.username !== null) {
      setGate({ status: 'unlocked', username: status.username });
    } else if (status.accountExists) {
      setGate({ status: 'locked' });
    } else {
      setGate({ status: 'setup' });
    }
  }, []);

  useEffect(() => {
    if (!isTauriAvailable()) {
      setGate({
        status: 'unavailable',
        message:
          'The backend is not reachable. Run the app with `pnpm tauri:dev` rather than opening ' +
          'the dev server in a browser.',
      });
      return;
    }

    let cancelled = false;
    getOwnerStatus()
      .then((status) => {
        if (!cancelled) applyStatus(status);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setGate({
          status: 'unavailable',
          message: error instanceof Error ? error.message : 'Could not reach the backend.',
        });
      });

    return () => {
      cancelled = true;
    };
  }, [applyStatus]);

  if (gate.status === 'loading') {
    return (
      <Centered>
        <p role="status" className="text-sm text-(--color-text-secondary)">
          Starting…
        </p>
      </Centered>
    );
  }

  if (gate.status === 'unavailable') {
    return (
      <Centered>
        <div role="alert" className="max-w-prose rounded border border-(--color-danger) p-4">
          <h1 className="mb-1 text-sm font-semibold text-(--color-danger)">Backend unavailable</h1>
          <p className="text-sm text-(--color-text-secondary)">{gate.message}</p>
        </div>
      </Centered>
    );
  }

  if (gate.status === 'setup' || gate.status === 'locked') {
    return (
      <Centered>
        <AuthPanel mode={gate.status} onAuthenticated={applyStatus} onToast={setToast} />
        <ToastBar
          toast={toast}
          onDismiss={() => {
            setToast(null);
          }}
        />
      </Centered>
    );
  }

  return (
    <div className="flex h-full">
      <nav
        aria-label="Sections"
        className="flex w-56 shrink-0 flex-col justify-between border-r border-(--color-border-subtle) bg-(--color-surface-sunken)"
      >
        <div>
          <div className="px-4 py-4">
            <h1 className="text-sm font-semibold">Remote Control</h1>
            <p className="text-xs text-(--color-text-secondary)">Private remote access</p>
          </div>

          <ul className="flex flex-col gap-0.5 px-2 pb-4">
            {NAV_ITEMS.map((item) => {
              const enabled = item.availableInPhase === null;
              return (
                <li key={item.id}>
                  <button
                    type="button"
                    disabled={!enabled}
                    aria-current={item.id === section ? 'page' : undefined}
                    onClick={() => {
                      if (enabled) setSection(item.id);
                    }}
                    title={
                      enabled ? undefined : `Arrives in development phase ${item.availableInPhase}`
                    }
                    className={
                      'flex w-full items-center justify-between rounded px-3 py-1.5 text-left text-sm ' +
                      (enabled
                        ? item.id === section
                          ? 'bg-(--color-surface-raised) font-medium'
                          : 'hover:bg-(--color-surface-raised)'
                        : 'cursor-not-allowed text-(--color-text-secondary) opacity-60')
                    }
                  >
                    <span>{item.label}</span>
                    {item.id === 'updates' && pendingVersion !== null && (
                      <span
                        aria-label={`Version ${pendingVersion} available`}
                        title={`Version ${pendingVersion} available`}
                        className="size-2 shrink-0 rounded-full bg-(--color-accent)"
                      />
                    )}
                    {!enabled && (
                      <span className="text-[10px] tabular-nums">P{item.availableInPhase}</span>
                    )}
                  </button>
                </li>
              );
            })}
          </ul>
        </div>

        <div className="border-t border-(--color-border-subtle) px-3 py-3">
          <p className="mb-2 truncate text-xs text-(--color-text-secondary)">
            Signed in as {gate.username}
          </p>
          <Button
            variant="ghost"
            onClick={() => {
              ownerLogout()
                .then(() => {
                  setGate({ status: 'locked' });
                })
                .catch(() => {
                  setToast({ kind: 'error', message: 'Could not lock the application.' });
                });
            }}
          >
            Lock
          </Button>
        </div>
      </nav>

      <main className="flex-1 overflow-auto">
        {pendingVersion !== null && section !== 'updates' && (
          <UpdateBanner
            version={pendingVersion}
            ready={isReadyToInstall(updates.status)}
            onOpen={() => {
              setSection('updates');
            }}
          />
        )}
        <div className="p-6">
          <Section id={section} onToast={setToast} onUpdateChange={updates.refresh} />
        </div>
      </main>

      <ToastBar
        toast={toast}
        onDismiss={() => {
          setToast(null);
        }}
      />
    </div>
  );
}

/**
 * Quiet, dismissible-by-acting call to action shown above any section while a
 * newer release is waiting. It is hidden on the Updates section itself, where
 * the same information is already the main content.
 */
function UpdateBanner({
  version,
  ready,
  onOpen,
}: {
  readonly version: string;
  readonly ready: boolean;
  readonly onOpen: () => void;
}): React.JSX.Element {
  return (
    <div
      role="status"
      className="flex flex-wrap items-center gap-3 border-b border-(--color-border-subtle) bg-(--color-surface-raised) px-6 py-2.5"
    >
      <span aria-hidden="true" className="size-2 shrink-0 rounded-full bg-(--color-accent)" />
      <p className="min-w-0 flex-1 text-sm">
        <span className="font-medium">Version {version} is available.</span>{' '}
        <span className="text-(--color-text-secondary)">
          {ready ? 'It is verified and ready to install.' : 'Review the changes and update.'}
        </span>
      </p>
      <Button variant="primary" onClick={onOpen}>
        {ready ? 'Install Now' : 'View Update'}
      </Button>
    </div>
  );
}

function Centered({ children }: { readonly children: React.ReactNode }): React.JSX.Element {
  return <div className="flex h-full items-center justify-center p-6">{children}</div>;
}

/** Owner account creation and sign-in. */
function AuthPanel({
  mode,
  onAuthenticated,
  onToast,
}: {
  readonly mode: 'setup' | 'locked';
  readonly onAuthenticated: (status: OwnerStatus) => void;
  readonly onToast: (toast: Toast) => void;
}): React.JSX.Element {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const setupMode = mode === 'setup';

  const submit = (event: React.FormEvent): void => {
    event.preventDefault();
    setError(null);

    if (setupMode && password !== confirm) {
      setError('The two passwords do not match.');
      return;
    }

    setBusy(true);
    const action = setupMode
      ? createOwner(username, password).then(() => ownerLogin(username, password))
      : ownerLogin(username, password);

    action
      .then((status) => {
        setPassword('');
        setConfirm('');
        if (setupMode) onToast({ kind: 'success', message: 'Owner account created.' });
        onAuthenticated(status);
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : 'Could not sign in.');
        setPassword('');
      })
      .finally(() => {
        setBusy(false);
      });
  };

  return (
    <form
      onSubmit={submit}
      className="w-full max-w-sm rounded border border-(--color-border-subtle) bg-(--color-surface-raised) p-6"
    >
      <h1 className="mb-1 text-base font-semibold">
        {setupMode ? 'Create your owner account' : 'Sign in'}
      </h1>
      <p className="mb-5 text-sm text-(--color-text-secondary)">
        {setupMode
          ? 'This account unlocks the application on this computer. There is no default password and no recovery — choose something you will not lose.'
          : 'Enter your owner password to unlock the application.'}
      </p>

      <label htmlFor="username" className="mb-1 block text-sm font-medium">
        Username
      </label>
      <input
        id="username"
        value={username}
        onChange={(event) => {
          setUsername(event.target.value);
        }}
        autoComplete="username"
        maxLength={64}
        required
        className="mb-4 w-full rounded border border-(--color-border-subtle) bg-(--color-surface) px-3 py-1.5 text-sm"
      />

      <label htmlFor="password" className="mb-1 block text-sm font-medium">
        Password
      </label>
      <input
        id="password"
        type="password"
        value={password}
        onChange={(event) => {
          setPassword(event.target.value);
        }}
        autoComplete={setupMode ? 'new-password' : 'current-password'}
        required
        className="w-full rounded border border-(--color-border-subtle) bg-(--color-surface) px-3 py-1.5 text-sm"
      />
      {setupMode && (
        <p className="mt-1 mb-4 text-xs text-(--color-text-secondary)">
          At least 12 characters. Stored as an Argon2id hash, never in plain text.
        </p>
      )}

      {setupMode && (
        <>
          <label htmlFor="confirm" className="mt-3 mb-1 block text-sm font-medium">
            Confirm password
          </label>
          <input
            id="confirm"
            type="password"
            value={confirm}
            onChange={(event) => {
              setConfirm(event.target.value);
            }}
            autoComplete="new-password"
            required
            className="mb-4 w-full rounded border border-(--color-border-subtle) bg-(--color-surface) px-3 py-1.5 text-sm"
          />
        </>
      )}

      {error !== null && (
        <p role="alert" className="mt-4 mb-2 text-sm text-(--color-danger)">
          {error}
        </p>
      )}

      <div className="mt-5">
        <Button type="submit" variant="primary" disabled={busy}>
          {busy ? 'Working…' : setupMode ? 'Create account' : 'Unlock'}
        </Button>
      </div>
    </form>
  );
}

/**
 * The screen for the selected sidebar section.
 *
 * Sections that are not yet built are unreachable — the sidebar disables them and says
 * which phase implements them — so this falls back to Home rather than rendering a
 * placeholder that would look like a broken page.
 */
function Section({
  id,
  onToast,
  onUpdateChange,
}: {
  readonly id: string;
  readonly onToast: (toast: Toast) => void;
  readonly onUpdateChange: () => void;
}): React.JSX.Element {
  switch (id) {
    case 'devices':
      return <DevicesScreen onToast={onToast} />;
    case 'monitoring':
      return <MonitoringScreen />;
    case 'updates':
      return <UpdateScreen onToast={onToast} onStatusChange={onUpdateChange} />;
    case 'terminal':
      return <TerminalScreen onToast={onToast} />;
    case 'files':
      return <FilesScreen onToast={onToast} />;
    default:
      return <HomeScreen />;
  }
}

/** The home overview. */
function HomeScreen(): React.JSX.Element {
  const [info, setInfo] = useState<ClientInfo | null>(null);

  useEffect(() => {
    let cancelled = false;
    getClientInfo()
      .then((value) => {
        if (!cancelled) setInfo(value);
      })
      .catch(() => {
        if (!cancelled) setInfo(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (info === null) {
    return (
      <p role="status" className="text-sm text-(--color-text-secondary)">
        Loading client information…
      </p>
    );
  }

  const rows: readonly (readonly [string, string])[] = [
    ['App version', info.appVersion],
    ['Protocol', `${String(info.protocolVersion.major)}.${String(info.protocolVersion.minor)}`],
    ['Hostname', info.hostname],
    ['Operating system', `${info.osVersion} (${info.osFamily})`],
    ['Architecture', info.architecture],
    ['Running elevated', info.elevated ? 'yes' : 'no'],
    ['Local database', info.databaseReady ? 'ready' : 'unavailable'],
  ];

  return (
    <section>
      <h2 className="mb-1 text-base font-semibold">This computer</h2>
      <p className="mb-4 max-w-prose text-sm text-(--color-text-secondary)">
        Device identity and pairing are ready. Connecting to a server needs the network transport,
        which arrives in phase 3; see <code>PROGRESS.md</code>.
      </p>

      <dl className="max-w-md divide-y divide-(--color-border-subtle) rounded border border-(--color-border-subtle)">
        {rows.map(([label, value]) => (
          <div key={label} className="flex justify-between gap-4 px-3 py-2 text-sm">
            <dt className="text-(--color-text-secondary)">{label}</dt>
            <dd className="font-mono">{value}</dd>
          </div>
        ))}
      </dl>

      {info.elevated && (
        <p role="alert" className="mt-4 max-w-prose text-sm text-(--color-warning)">
          This client is running with administrator privileges. That is not required and not
          recommended — privileged operations are routed through the agent service instead.
        </p>
      )}
    </section>
  );
}
