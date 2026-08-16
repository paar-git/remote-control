/**
 * This machine's identity and reachability, for chrome that must stay current
 * regardless of which category is open.
 */

import { useCallback, useEffect, useState } from 'react';

import {
  getClientInfo,
  getHostStatus,
  getLocalIdentity,
  listRecent,
  type ClientInfo,
  type HostStatus,
  type LocalIdentity,
  type Recent,
} from './api.js';

export interface HostSnapshot {
  readonly status: HostStatus | null;
  readonly identity: LocalIdentity | null;
  readonly os: ClientInfo['osFamily'] | undefined;
  readonly hostname: string | undefined;
  readonly recent: readonly Recent[];
  readonly refresh: () => void;
}

export function useHostSnapshot(enabled: boolean, epoch = 0): HostSnapshot {
  const [status, setStatus] = useState<HostStatus | null>(null);
  const [identity, setIdentity] = useState<LocalIdentity | null>(null);
  const [os, setOs] = useState<ClientInfo['osFamily'] | undefined>(undefined);
  const [hostname, setHostname] = useState<string | undefined>(undefined);
  const [recent, setRecent] = useState<readonly Recent[]>([]);

  const refresh = useCallback(() => {
    if (!enabled) return;
    getHostStatus()
      .then(setStatus)
      .catch(() => {
        setStatus(null);
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
    listRecent()
      .then(setRecent)
      .catch(() => {
        setRecent([]);
      });
  }, [enabled]);

  useEffect(() => {
    refresh();
  }, [refresh, epoch]);

  return { status, identity, os, hostname, recent, refresh };
}
