/**
 * Application root.
 *
 * There is no account and no login. The one gate that remains is whether the backend
 * can be reached at all, which is a real condition — the webview can load without its
 * Tauri host ever responding — not a placeholder for a deleted owner account.
 *
 * # Two states, and only two
 *
 * Out of session the window is {@link MainWindow}: two cards and a recent list. Inside
 * a session it becomes the remote machine — {@link SessionScreen} replaces the entire
 * frame. That is the design: once you are connected, the interface gets out of the way.
 *
 * `inSession` switches between them and is never set unless the backend reports a live
 * connection. A session that ends, deliberately or not, drops the window back to the
 * main one, because the backend's state is the authority and not this flag.
 *
 * # What lives here
 *
 * Only what more than one state needs and what must agree across them: the live
 * connection, the pending update, the toast bar, and the accept dialog. The accept
 * dialog in particular belongs here rather than in `MainWindow` — a connection request
 * arrives whether or not you are looking at the main window, and it must be answerable
 * from inside a session too.
 */

import { AlertTriangle, MonitorCog } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';

import { AcceptDialog } from './AcceptDialog';
import { getClientInfo, isConnected } from './api.js';
import { isTauriAvailable } from './ipc.js';
import { MainWindow } from './MainWindow';
import { SessionScreen } from './SessionScreen';
import { SettingsDialog } from './SettingsDialog';
import { useConnectionState } from './useConnection.js';
import { isReadyToInstall, pendingUpdateVersion } from './updates.js';
import { useUpdateWatcher } from './useUpdateWatcher.js';
import { ToastBar, type Toast } from './ui';

type Gate =
  | { readonly status: 'loading' }
  | { readonly status: 'unavailable'; readonly message: string }
  | { readonly status: 'ready' };

export default function App(): React.JSX.Element {
  const [gate, setGate] = useState<Gate>({ status: 'loading' });
  const [toast, setToast] = useState<Toast | null>(null);
  const [inSession, setInSession] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);

  const ready = gate.status === 'ready';

  // Only poll once the backend is known reachable; before that every call would just
  // fail the same way the reachability probe already did.
  const updates = useUpdateWatcher(ready);
  const pendingVersion = pendingUpdateVersion(updates.status);
  const connection = useConnectionState(ready);
  const live = isConnected(connection.state);

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
    // `client_info` is a cheap, side-effect-free call — it exists to answer this
    // question, not because its value is needed here.
    getClientInfo()
      .then(() => {
        if (!cancelled) setGate({ status: 'ready' });
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
  }, []);

  // A session that ends — deliberately or not — must not leave the window pretending to
  // be a remote machine. The backend's state is the authority.
  useEffect(() => {
    if (!live) setInSession(false);
  }, [live]);

  const dismissToast = useCallback(() => {
    setToast(null);
  }, []);

  const closeSettings = useCallback(() => {
    setSettingsOpen(false);
  }, []);

  if (gate.status === 'loading') return <Splash />;

  if (gate.status === 'unavailable') return <BackendUnavailable message={gate.message} />;

  return (
    <>
      {inSession && live ? (
        // The session owns the whole window: no title bar, no cards over it.
        <SessionScreen
          connection={connection.state}
          deviceName={null}
          permissions={connection.state.state === 'connected' ? connection.state.permissions : []}
          onToast={setToast}
          onLeave={() => {
            setInSession(false);
          }}
        />
      ) : (
        <div className="flex h-full flex-col">
          {pendingVersion !== null && (
            <UpdateBanner version={pendingVersion} ready={isReadyToInstall(updates.status)} />
          )}
          <div className="min-h-0 flex-1">
            <MainWindow
              onConnected={() => {
                setInSession(true);
              }}
              onToast={setToast}
              onOpenSettings={() => {
                setSettingsOpen(true);
              }}
              connection={connection.state}
            />
          </div>
        </div>
      )}

      {/*
       * Outside the two states on purpose. A connection request arrives whether or not
       * anyone is looking at the main window, and it has to be answerable from inside a
       * session as well.
       */}
      <AcceptDialog onToast={setToast} />

      {settingsOpen && <SettingsDialog onClose={closeSettings} onToast={setToast} />}

      <ToastBar toast={toast} onDismiss={dismissToast} />
    </>
  );
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

/** The one failure the root itself has to render: no backend at all. */
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
 * A quiet strip under the title bar while a newer release is waiting.
 *
 * Installing is a settings action, so this says what is true and points there rather
 * than offering a second place to do it.
 */
function UpdateBanner({
  version,
  ready,
}: {
  readonly version: string;
  readonly ready: boolean;
}): React.JSX.Element {
  return (
    <div
      role="status"
      className="flex flex-wrap items-center gap-3 border-b border-(--color-border) bg-(--color-accent-soft) px-4 py-2"
    >
      <span aria-hidden="true" className="size-2 shrink-0 rounded-full bg-(--color-accent)" />
      <p className="min-w-0 flex-1 text-sm">
        <span className="font-medium">Version {version} is available.</span>{' '}
        <span className="text-(--color-text-secondary)">
          {ready ? 'It is verified and ready to install.' : 'Open settings to review it.'}
        </span>
      </p>
    </div>
  );
}
