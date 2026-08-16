/**
 * Home workspace: this machine, quick access, recent devices, session activity.
 */

import { useCallback, useEffect, useState } from 'react';

import {
  getClientInfo,
  getHostStatus,
  getLocalIdentity,
  listRecent,
  listSessionHistory,
  probeDevice,
  setAccepting,
  type ClientInfo,
  type HostStatus,
  type LocalIdentity,
  type Presence,
  type Recent,
  type SessionRecord,
} from './api.js';
import { Panel, QuickAccessPanel, RecentDevicesPanel, SessionActivityPanel } from './chrome';
import { ThisDevice } from './ThisDevice';
import type { Toast } from './ui';

export function RemoteControlPage({
  onConnect,
  connectBusy,
  onToast,
  onViewAllDevices,
  onViewSessions,
  onOpenSettings,
  onInvite,
  onHostChanged,
  hostEpoch = 0,
}: {
  readonly onConnect: (address: string) => void;
  readonly connectBusy: boolean;
  readonly onToast: (toast: Toast) => void;
  readonly onViewAllDevices: () => void;
  readonly onViewSessions: () => void;
  readonly onOpenSettings: () => void;
  readonly onInvite: () => void;
  readonly onHostChanged?: (() => void) | undefined;
  readonly hostEpoch?: number | undefined;
}): React.JSX.Element {
  const [status, setStatus] = useState<HostStatus | null>(null);
  const [identity, setIdentity] = useState<LocalIdentity | null>(null);
  const [os, setOs] = useState<ClientInfo['osFamily'] | undefined>(undefined);
  const [hostname, setHostname] = useState<string | undefined>(undefined);
  const [recent, setRecent] = useState<readonly Recent[]>([]);
  const [presence, setPresence] = useState<Readonly<Record<string, Presence>>>({});
  const [history, setHistory] = useState<readonly SessionRecord[]>([]);
  const [toggling, setToggling] = useState(false);

  const refresh = useCallback(() => {
    getHostStatus()
      .then(setStatus)
      .catch((error: unknown) => {
        onToast({
          kind: 'error',
          message: error instanceof Error ? error.message : 'Could not read this machine’s state.',
        });
      });
    getLocalIdentity()
      .then(setIdentity)
      .catch(() => {
        setIdentity(null);
      });
    getClientInfo()
      .then((info) => {
        setOs(info.osFamily);
        setHostname(info.hostname);
      })
      .catch(() => {
        setOs(undefined);
        setHostname(undefined);
      });
    listSessionHistory()
      .then(setHistory)
      .catch(() => {
        setHistory([]);
      });
    let cancelled = false;
    listRecent()
      .then((entries) => {
        if (cancelled) return;
        setRecent(entries);
        for (const entry of entries.slice(0, 5)) {
          setPresence((current) => ({ ...current, [entry.address]: 'checking' }));
          probeDevice(entry.address)
            .then((result) => {
              if (!cancelled) {
                setPresence((current) => ({ ...current, [entry.address]: result }));
              }
            })
            .catch(() => {
              if (!cancelled) {
                setPresence((current) => ({ ...current, [entry.address]: 'offline' }));
              }
            });
        }
      })
      .catch(() => {
        if (!cancelled) setRecent([]);
      });
    return () => {
      cancelled = true;
    };
  }, [onToast]);

  useEffect(() => {
    const stop = refresh();
    return stop;
  }, [refresh, hostEpoch]);

  const toggleAccepting = (next: boolean): void => {
    setToggling(true);
    setAccepting(next)
      .then((updated) => {
        setStatus(updated);
        onHostChanged?.();
      })
      .catch((error: unknown) => {
        onToast({
          kind: 'error',
          message:
            error instanceof Error ? error.message : 'Could not change incoming connections.',
        });
      })
      .finally(() => {
        setToggling(false);
      });
  };

  return (
    <div className="rc-workspace min-h-0 flex-1">
      {status !== null ? (
        <ThisDevice
          status={status}
          identity={identity}
          os={os}
          hostname={hostname}
          onToggleAccepting={toggleAccepting}
          toggling={toggling}
        />
      ) : (
        <Panel />
      )}
      <RecentDevicesPanel
        recent={recent}
        presence={presence}
        busy={connectBusy}
        onConnect={onConnect}
        onViewAll={onViewAllDevices}
      />
      <QuickAccessPanel onUnattended={onOpenSettings} onInvite={onInvite} />
      <SessionActivityPanel records={history} onViewAll={onViewSessions} />
    </div>
  );
}
