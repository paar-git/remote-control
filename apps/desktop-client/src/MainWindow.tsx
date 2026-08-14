/**
 * The window you see when you are not in a session.
 *
 * Connect is the primary surface. This device and trusted machines sit underneath;
 * recent sessions are a compact list, not a half-empty card.
 */

import { Moon, Settings, Sun } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';

import {
  connectToAddress,
  getClientInfo,
  getHostStatus,
  getLocalIdentity,
  listRecent,
  setAccepting,
  type ClientInfo,
  type ConnectionState,
  type HostStatus,
  type Recent,
} from './api.js';
import { AppSidebar } from './AppSidebar';
import { RecentList } from './RecentList';
import { RemoteDeskCard } from './RemoteDeskCard';
import { ThisDeskCard } from './ThisDeskCard';
import { TrustedDevices } from './TrustedDevices';
import { applyTheme, loadTheme, resolvedTheme, saveTheme, type ThemePreference } from './theme.js';
import { IconButton, type Toast } from './ui';

export function MainWindow({
  onConnected,
  onToast,
  onOpenSettings,
  connection,
}: {
  readonly onConnected: () => void;
  readonly onToast: (toast: Toast) => void;
  readonly onOpenSettings: () => void;
  readonly connection: ConnectionState;
}): React.JSX.Element {
  const [status, setStatus] = useState<HostStatus | null>(null);
  const [recent, setRecent] = useState<readonly Recent[]>([]);
  const [deviceIdSource, setDeviceIdSource] = useState<string | null>(null);
  const [os, setOs] = useState<ClientInfo['osFamily'] | undefined>(undefined);
  const [busy, setBusy] = useState(false);
  const [toggling, setToggling] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const [theme, setTheme] = useState<ThemePreference>(loadTheme);

  const refresh = useCallback(() => {
    getHostStatus()
      .then(setStatus)
      .catch((error: unknown) => {
        onToast({
          kind: 'error',
          message: error instanceof Error ? error.message : 'Could not read this machine’s state.',
        });
      });
    listRecent()
      .then(setRecent)
      .catch(() => {
        setRecent([]);
      });
    getLocalIdentity()
      .then((identity) => {
        setDeviceIdSource(identity.identityFingerprint);
      })
      .catch(() => {
        setDeviceIdSource(null);
      });
    getClientInfo()
      .then((info) => {
        setOs(info.osFamily);
      })
      .catch(() => {
        setOs(undefined);
      });
  }, [onToast]);

  useEffect(refresh, [refresh]);

  useEffect(() => {
    applyTheme(theme);
    if (theme !== 'system' || typeof window.matchMedia !== 'function') return;
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const onChange = (): void => {
      applyTheme('system');
    };
    media.addEventListener('change', onChange);
    return () => {
      media.removeEventListener('change', onChange);
    };
  }, [theme]);

  const connect = useCallback(
    (address: string) => {
      setBusy(true);
      setFailure(null);
      connectToAddress(address, null)
        .then(() => {
          refresh();
          onConnected();
        })
        .catch((error: unknown) => {
          setFailure(error instanceof Error ? error.message : 'That machine could not be reached.');
        })
        .finally(() => {
          setBusy(false);
        });
    },
    [onConnected, refresh],
  );

  const toggleAccepting = useCallback(
    (next: boolean) => {
      setToggling(true);
      setAccepting(next)
        .then(setStatus)
        .catch((error: unknown) => {
          onToast({
            kind: 'error',
            message: error instanceof Error ? error.message : 'Could not change incoming connections.',
          });
        })
        .finally(() => {
          setToggling(false);
        });
    },
    [onToast],
  );

  const cycleTheme = (): void => {
    const next: ThemePreference = resolvedTheme(theme) === 'dark' ? 'light' : 'dark';
    saveTheme(next);
    setTheme(next);
  };

  return (
    <div className="flex h-full bg-(--color-page)">
      <AppSidebar
        onOpenSettings={onOpenSettings}
        onShowDevices={() => {
          document.getElementById('recent-sessions')?.scrollIntoView({ behavior: 'smooth' });
        }}
        sessionLive={connection.state === 'connected'}
      />

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center gap-3 px-8 py-5">
          <h1 className="min-w-0 flex-1 truncate text-2xl font-semibold tracking-tight">
            Remote Control
          </h1>
          <IconButton
            icon={resolvedTheme(theme) === 'dark' ? Sun : Moon}
            label={resolvedTheme(theme) === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
            onClick={cycleTheme}
          />
          <IconButton icon={Settings} label="Settings" onClick={onOpenSettings} />
        </header>

        <div className="flex min-h-0 flex-1 flex-col gap-8 overflow-y-auto px-8 pb-10">
          <RemoteDeskCard
            onConnect={connect}
            busy={busy}
            error={failure}
            connection={connection}
            suggestions={recent}
          />

          <div className="grid gap-5 lg:grid-cols-2">
            <ThisDeskCard
              status={status}
              deviceIdSource={deviceIdSource}
              os={os}
              onToggleAccepting={toggleAccepting}
              toggling={toggling}
            />
            <TrustedDevices entries={recent} onConnect={connect} busy={busy} />
          </div>

          <RecentList entries={recent} onConnect={connect} busy={busy} />
        </div>
      </div>
    </div>
  );
}
