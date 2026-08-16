/**
 * Application root.
 *
 * There is no account and no login. The one gate that remains is whether the backend
 * can be reached at all, which is a real condition — the webview can load without its
 * Tauri host ever responding — not a placeholder for a deleted owner account.
 *
 * Out of session the window is four categories inside {@link AppShell}, under a
 * persistent connect row and this machine's address. Inside a
 * session it becomes the remote machine — {@link SessionScreen} replaces the entire
 * frame. That is the design: once you are connected, the interface gets out of the way.
 *
 * The accept dialog belongs here rather than in a page — a connection request arrives
 * whether or not you are looking at the home page, and it must be answerable from
 * inside a session too.
 */

import { AlertTriangle } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';

import { AcceptDialog } from './AcceptDialog';
import { AppShell } from './AppShell';
import {
  disconnectInbound,
  emergencyDisconnect,
  getClientInfo,
  isConnected,
  listInboundSessions,
  type InboundSession,
} from './api.js';
import { invitationText, primaryAddress, RcMark } from './chrome';
import { formatDeviceId } from './format.js';
import { InboundSessionBanner } from './InboundSessionBanner';
import { isTauriAvailable } from './ipc.js';
import { MyDevicesPage } from './MyDevicesPage';
import { type View } from './navigation.js';
import { RemoteControlPage } from './RemoteControlPage';
import { SessionScreen } from './SessionScreen';
import { SessionsPage } from './SessionsPage';
import { SettingsPage } from './SettingsPage';
import { useConnectForm } from './useConnectForm.js';
import { useConnectionState } from './useConnection.js';
import { useHostSnapshot } from './useHostSnapshot.js';
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
  const [view, setView] = useState<View>('remote-control');
  const [inbound, setInbound] = useState<readonly InboundSession[]>([]);
  const [hostEpoch, setHostEpoch] = useState(0);

  const ready = gate.status === 'ready';

  const updates = useUpdateWatcher(ready);
  const pendingVersion = pendingUpdateVersion(updates.status);
  const connection = useConnectionState(ready);
  const live = isConnected(connection.state);
  const host = useHostSnapshot(ready, hostEpoch);
  const form = useConnectForm({
    connection: connection.state,
    onConnection: connection.set,
    onToast: setToast,
  });

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

  const wasLive = useRef(false);
  useEffect(() => {
    if (live && !wasLive.current) {
      setInSession(true);
      host.refresh();
    }
    if (!live) setInSession(false);
    wasLive.current = live;
  }, [live]);

  const invite = useCallback(() => {
    const deviceId =
      host.identity === null ? '—' : formatDeviceId(host.identity.identityFingerprint);
    const address = host.status === null ? null : primaryAddress(host.status.addresses);
    const text = invitationText(host.status?.machineName ?? 'This device', deviceId, address);
    navigator.clipboard.writeText(text).then(
      () => {
        setToast({ kind: 'success', message: 'Invitation copied.' });
      },
      () => {
        setToast({ kind: 'error', message: 'Could not copy the invitation.' });
      },
    );
  }, [host.identity, host.status]);

  useEffect(() => {
    if (!ready) return;
    let cancelled = false;
    const poll = (): void => {
      listInboundSessions()
        .then((sessions) => {
          if (!cancelled) setInbound(sessions);
        })
        .catch(() => {
          if (!cancelled) setInbound([]);
        });
    };
    poll();
    const timer = window.setInterval(poll, 2000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [ready]);

  const dismissToast = useCallback(() => {
    setToast(null);
  }, []);

  const onDisconnectInbound = useCallback((sessionId: string) => {
    disconnectInbound(sessionId)
      .then(() => {
        listInboundSessions()
          .then(setInbound)
          .catch(() => {
            setInbound([]);
          });
      })
      .catch((error: unknown) => {
        setToast({
          kind: 'error',
          message: error instanceof Error ? error.message : 'Could not disconnect that session.',
        });
      });
  }, []);

  const onEmergency = useCallback(() => {
    emergencyDisconnect()
      .then(() => {
        setInbound([]);
        setHostEpoch((epoch) => epoch + 1);
      })
      .catch((error: unknown) => {
        setToast({
          kind: 'error',
          message: error instanceof Error ? error.message : 'Emergency disconnect failed.',
        });
      });
  }, []);

  if (gate.status === 'loading') return <Splash />;

  if (gate.status === 'unavailable') return <BackendUnavailable message={gate.message} />;

  const updateBanner =
    pendingVersion !== null ? (
      <UpdateBanner
        version={pendingVersion}
        ready={isReadyToInstall(updates.status)}
        onOpenSettings={() => {
          setView('settings');
        }}
      />
    ) : null;

  const inboundBanner = (
    <InboundSessionBanner
      sessions={inbound}
      onDisconnect={onDisconnectInbound}
      onEmergency={onEmergency}
    />
  );

  return (
    <div className="flex h-full min-h-0 flex-col">
      {inboundBanner}
      {inSession && live ? (
        <div className="min-h-0 flex-1">
          <SessionScreen
            connection={connection.state}
            deviceName={connection.state.state === 'connected' ? connection.state.deviceName : null}
            permissions={connection.state.state === 'connected' ? connection.state.permissions : []}
            onToast={setToast}
            onLeave={() => {
              setInSession(false);
            }}
          />
        </div>
      ) : (
        <AppShell
          view={view}
          onNavigate={setView}
          banner={updateBanner}
          connection={connection.state}
          status={host.status}
          identity={host.identity}
          recent={host.recent}
          address={form.address}
          onAddressChange={form.setAddress}
          onSubmit={form.submit}
          parseError={form.parseError}
          busy={form.busy}
          failed={form.failed}
          inputRef={form.inputRef}
          onPickRecent={form.connect}
          onConnectWithPassword={form.submitWithPassword}
          onNewSession={form.clear}
          onInvite={invite}
        >
          {view === 'remote-control' && (
            <RemoteControlPage
              onConnect={form.connect}
              connectBusy={form.busy}
              onToast={setToast}
              onHostChanged={host.refresh}
              onViewAllDevices={() => {
                setView('my-devices');
              }}
              onViewSessions={() => {
                setView('sessions');
              }}
              onOpenSettings={() => {
                setView('settings');
              }}
              onInvite={invite}
              hostEpoch={hostEpoch}
            />
          )}
          {view === 'my-devices' && (
            <MyDevicesPage
              onConnect={() => {
                setInSession(true);
              }}
              onConnection={connection.set}
              onToast={setToast}
            />
          )}
          {view === 'sessions' && (
            <SessionsPage
              inbound={inbound}
              onDisconnectInbound={onDisconnectInbound}
              onToast={setToast}
            />
          )}
          {view === 'settings' && (
            <SettingsPage
              onToast={setToast}
              onViewDevices={() => {
                setView('my-devices');
              }}
              hostEpoch={hostEpoch}
            />
          )}
        </AppShell>
      )}

      <AcceptDialog onToast={setToast} />

      <ToastBar toast={toast} onDismiss={dismissToast} />
    </div>
  );
}

function Splash(): React.JSX.Element {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-3 bg-(--color-page)">
      <RcMark size={28} />
      <p role="status" className="text-sm text-(--color-text-secondary)">
        Starting…
      </p>
    </div>
  );
}

function BackendUnavailable({ message }: { readonly message: string }): React.JSX.Element {
  return (
    <div className="flex h-full items-center justify-center bg-(--color-page) p-6">
      <div
        role="alert"
        className="w-full max-w-md rounded-[4px] border border-(--color-danger)/40 bg-(--color-card) p-5"
      >
        <div className="mb-2 flex items-center gap-2.5">
          <span className="flex size-8 items-center justify-center rounded-[4px] bg-(--color-danger-soft) text-(--color-danger)">
            <AlertTriangle aria-hidden="true" className="size-4" />
          </span>
          <h1 className="text-base font-semibold">Backend unavailable</h1>
        </div>
        <p className="text-sm text-(--color-text-secondary)">{message}</p>
      </div>
    </div>
  );
}

function UpdateBanner({
  version,
  ready,
  onOpenSettings,
}: {
  readonly version: string;
  readonly ready: boolean;
  readonly onOpenSettings: () => void;
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
      <button
        type="button"
        className="text-sm font-medium text-(--color-accent) hover:underline"
        onClick={onOpenSettings}
      >
        Settings
      </button>
    </div>
  );
}
