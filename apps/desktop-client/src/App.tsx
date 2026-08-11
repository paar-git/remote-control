/**
 * Application shell.
 *
 * The app is gated: on first run it asks for an owner account, thereafter it asks for
 * the owner password. Only once unlocked does the shell appear.
 *
 * # Two modes
 *
 * Out of session the window is a normal application: sidebar, toolbar, content. Inside a
 * session it becomes the remote computer — {@link SessionScreen} replaces the entire
 * frame, chrome and all. That is the whole point of the design: once you are connected,
 * the interface gets out of the way. `inSession` is what switches between the two, and it
 * is never set unless the backend reports a live connection.
 *
 * Two pieces of state live here rather than in the screens, because more than one screen
 * needs them and they must agree: the live connection, polled once and shared, and the
 * pending update, which drives the sidebar badge, the toolbar bell and the banner.
 */

import { AlertTriangle, MonitorCog } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';

import {
  type OwnerStatus,
  getClientInfo,
  getOwnerStatus,
  isConnected,
  ownerLogout,
} from './api.js';
import { AuthScreen } from './AuthScreen';
import FilesScreen from './FilesScreen';
import MonitoringScreen from './MonitoringScreen';
import { RemoteAccessScreen } from './RemoteAccessScreen';
import { SessionScreen } from './SessionScreen';
import { ThisComputerScreen } from './ThisComputerScreen';
import UpdateScreen from './UpdateScreen';
import { isTauriAvailable } from './ipc.js';
import { AppShell } from './shell/AppShell';
import { DEFAULT_SECTION, isSectionAvailable, sectionForShortcut } from './shell/navigation';
import { Sidebar, type ServiceStatus } from './shell/Sidebar';
import { TopBar } from './shell/TopBar';
import { type Connection, useConnectionState } from './useConnection.js';
import { isReadyToInstall, pendingUpdateVersion } from './updates.js';
import { useUpdateWatcher } from './useUpdateWatcher.js';
import { Button, ToastBar, type Toast } from './ui';

type Gate =
  | { readonly status: 'loading' }
  | { readonly status: 'unavailable'; readonly message: string }
  | { readonly status: 'setup' }
  | { readonly status: 'locked' }
  | { readonly status: 'unlocked'; readonly username: string };

/** Remembered so the window opens the way it was left. */
const COLLAPSED_KEY = 'rc.sidebar.collapsed';

export default function App(): React.JSX.Element {
  const [gate, setGate] = useState<Gate>({ status: 'loading' });
  const [section, setSection] = useState(DEFAULT_SECTION);
  const [toast, setToast] = useState<Toast | null>(null);
  const [inSession, setInSession] = useState(false);
  const [sessionDevice, setSessionDevice] = useState<string | null>(null);
  const [collapsed, setCollapsed] = useState(
    () => globalThis.localStorage?.getItem(COLLAPSED_KEY) === 'true',
  );

  const unlocked = gate.status === 'unlocked';

  // Only poll for releases once the app is unlocked; before that the backend
  // refuses the capability check anyway.
  const updates = useUpdateWatcher(unlocked);
  const pendingVersion = pendingUpdateVersion(updates.status);
  const connection = useConnectionState(unlocked);
  const service = useServiceStatus(gate.status);
  const live = isConnected(connection.state);

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

  // A session that ends — deliberately or not — must not leave the window pretending to
  // be a remote computer. The backend's state is the authority.
  useEffect(() => {
    if (!live) {
      setInSession(false);
      setSessionDevice(null);
    }
  }, [live]);

  const navigate = useCallback((id: string) => {
    // Guarded rather than trusted: a shortcut or a panel button must not be able to
    // route to a section the sidebar itself refuses to open.
    if (!isSectionAvailable(id)) return;
    setInSession(false);
    setSection(id);
  }, []);

  // Shortcuts are only advertised on items that are bound, and only bound while the app
  // is unlocked — nothing behind the gate should be reachable by keyboard.
  useEffect(() => {
    if (!unlocked) return;

    const onKey = (event: KeyboardEvent): void => {
      const target = sectionForShortcut(event);
      if (target === undefined) return;
      event.preventDefault();
      navigate(target);
    };

    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('keydown', onKey);
    };
  }, [unlocked, navigate]);

  const toggleCollapsed = useCallback(() => {
    setCollapsed((current) => {
      const next = !current;
      globalThis.localStorage?.setItem(COLLAPSED_KEY, String(next));
      return next;
    });
  }, []);

  const lock = useCallback(() => {
    ownerLogout()
      .then(() => {
        setGate({ status: 'locked' });
        setInSession(false);
        setSection(DEFAULT_SECTION);
      })
      .catch(() => {
        setToast({ kind: 'error', message: 'Could not lock the application.' });
      });
  }, []);

  const dismissToast = useCallback(() => {
    setToast(null);
  }, []);

  if (gate.status === 'loading') return <Splash />;

  if (gate.status === 'unavailable') return <BackendUnavailable message={gate.message} />;

  if (gate.status === 'setup' || gate.status === 'locked') {
    return (
      <>
        <AuthScreen mode={gate.status} onAuthenticated={applyStatus} onToast={setToast} />
        <ToastBar toast={toast} onDismiss={dismissToast} />
      </>
    );
  }

  // The session owns the whole window, with no sidebar and no toolbar over it.
  if (inSession && live) {
    return (
      <>
        <SessionScreen
          connection={connection.state}
          deviceName={sessionDevice}
          onToast={setToast}
          onLeave={() => {
            setInSession(false);
          }}
          onOpenTool={navigate}
        />
        <ToastBar toast={toast} onDismiss={dismissToast} />
      </>
    );
  }

  return (
    <>
      <AppShell
        sidebar={
          <Sidebar
            section={section}
            onSelect={navigate}
            collapsed={collapsed}
            onToggleCollapsed={toggleCollapsed}
            username={gate.username}
            onLock={lock}
            updateBadge={pendingVersion}
            service={service}
            sessionActive={live}
          />
        }
        toolbar={
          <TopBar
            section={section}
            connection={connection.state}
            pendingVersion={pendingVersion}
            onOpenUpdates={() => {
              navigate('updates');
            }}
            onResumeSession={
              live
                ? () => {
                    setInSession(true);
                  }
                : undefined
            }
          />
        }
        banner={
          pendingVersion !== null && section !== 'updates' ? (
            <UpdateBanner
              version={pendingVersion}
              ready={isReadyToInstall(updates.status)}
              onOpen={() => {
                navigate('updates');
              }}
            />
          ) : undefined
        }
      >
        <Section
          id={section}
          connection={connection}
          onNavigate={navigate}
          onToast={setToast}
          onUpdateChange={updates.refresh}
          onEnterSession={(name) => {
            // `null` means "resume whatever is open", so the name already recorded
            // when the session started is kept rather than blanked.
            if (name !== null) setSessionDevice(name);
            setInSession(true);
          }}
        />
      </AppShell>

      <ToastBar toast={toast} onDismiss={dismissToast} />
    </>
  );
}

/**
 * Whether this installation is working, summarised for the sidebar.
 *
 * Derived from what the client can actually verify about itself — the backend answered,
 * and its local database opened — rather than from a service it does not run. The client
 * is not the agent; claiming "service online" here would be describing another program.
 */
function useServiceStatus(gate: Gate['status']): ServiceStatus {
  const [databaseReady, setDatabaseReady] = useState<boolean | null>(null);

  useEffect(() => {
    if (gate !== 'unlocked') return;
    let cancelled = false;
    getClientInfo()
      .then((info) => {
        if (!cancelled) setDatabaseReady(info.databaseReady);
      })
      .catch(() => {
        if (!cancelled) setDatabaseReady(false);
      });
    return () => {
      cancelled = true;
    };
  }, [gate]);

  if (databaseReady === null) {
    return { tone: 'busy', label: 'Starting', detail: 'Reading this computer’s state.' };
  }
  if (!databaseReady) {
    return {
      tone: 'danger',
      label: 'Storage error',
      detail: 'The local database could not be opened, so nothing can be saved.',
    };
  }
  return {
    tone: 'ready',
    label: 'Client ready',
    detail: 'The client backend is running and its local database is open.',
  };
}

/** The first frame, before the backend has answered. */
function Splash(): React.JSX.Element {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-3 bg-(--color-page)">
      <span className="flex size-11 items-center justify-center rounded-2xl bg-(--color-accent) text-(--color-accent-text)">
        <MonitorCog aria-hidden="true" className="size-5.5" />
      </span>
      <p role="status" className="text-sm text-(--color-text-secondary)">
        Starting…
      </p>
    </div>
  );
}

/** The one failure the shell itself has to render: no backend at all. */
function BackendUnavailable({ message }: { readonly message: string }): React.JSX.Element {
  return (
    <div className="flex h-full items-center justify-center bg-(--color-page) p-6">
      <div
        role="alert"
        className="w-full max-w-md rounded-xl border border-(--color-danger)/40 bg-(--color-card) p-5"
      >
        <div className="mb-2 flex items-center gap-2.5">
          <span className="flex size-8 items-center justify-center rounded-lg bg-(--color-danger-soft) text-(--color-danger)">
            <AlertTriangle aria-hidden="true" className="size-4" />
          </span>
          <h1 className="text-base font-semibold">Backend unavailable</h1>
        </div>
        <p className="text-sm text-(--color-text-secondary)">{message}</p>
      </div>
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
      className="flex flex-wrap items-center gap-3 border-b border-(--color-border) bg-(--color-accent-soft) px-5 py-2.5"
    >
      <span aria-hidden="true" className="size-2 shrink-0 rounded-full bg-(--color-accent)" />
      <p className="min-w-0 flex-1 text-sm">
        <span className="font-medium">Version {version} is available.</span>{' '}
        <span className="text-(--color-text-secondary)">
          {ready ? 'It is verified and ready to install.' : 'Review the changes and update.'}
        </span>
      </p>
      <Button variant="primary" size="sm" onClick={onOpen}>
        {ready ? 'Install now' : 'View update'}
      </Button>
    </div>
  );
}

/**
 * The screen for the selected sidebar section.
 *
 * Sections that are not yet built are unreachable — the sidebar disables them, the
 * shortcuts skip them and `navigate` refuses them — so this falls back to Remote Access
 * rather than rendering a placeholder that would look like a broken page.
 */
function Section({
  id,
  connection,
  onNavigate,
  onToast,
  onUpdateChange,
  onEnterSession,
}: {
  readonly id: string;
  readonly connection: Connection;
  readonly onNavigate: (section: string) => void;
  readonly onToast: (toast: Toast) => void;
  readonly onUpdateChange: () => void;
  readonly onEnterSession: (deviceName: string | null) => void;
}): React.JSX.Element {
  switch (id) {
    case 'this-computer':
      return <ThisComputerScreen connection={connection.state} onNavigate={onNavigate} />;
    case 'monitoring':
      return <MonitoringScreen />;
    case 'updates':
      return <UpdateScreen onToast={onToast} onStatusChange={onUpdateChange} />;
    case 'files':
      return <FilesScreen onToast={onToast} />;
    default:
      return (
        <RemoteAccessScreen
          onToast={onToast}
          connection={connection}
          onOpenSession={onEnterSession}
        />
      );
  }
}
