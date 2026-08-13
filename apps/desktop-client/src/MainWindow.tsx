/**
 * The window you see when you are not in a session.
 *
 * Two cards — this machine, and the one you want to reach — above a list of machines
 * you have reached before. That is the whole surface. It replaced an eleven-section
 * sidebar because everything else this application does either belongs to a live
 * session or belongs in settings.
 *
 * # Where state lives
 *
 * The host status and the recent list are read here and passed down, because both are
 * backend facts that more than one child renders and they must agree. Neither child
 * fetches for itself.
 *
 * A connection attempt is owned here too: it is the one action that changes what the
 * whole window is, so the busy flag and the failure both have to outlive whichever card
 * started it.
 */

import { Settings } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';

import {
  connectToAddress,
  getHostStatus,
  listRecent,
  type HostStatus,
  type Recent,
} from './api.js';
import { RecentList } from './RecentList';
import { RemoteDeskCard } from './RemoteDeskCard';
import { ThisDeskCard } from './ThisDeskCard';
import { IconButton, type Toast } from './ui';

export function MainWindow({
  onConnected,
  onToast,
  onOpenSettings,
}: {
  /** Called once a connection is live, so the root can hand the window to the session. */
  readonly onConnected: () => void;
  readonly onToast: (toast: Toast) => void;
  readonly onOpenSettings: () => void;
}): React.JSX.Element {
  const [status, setStatus] = useState<HostStatus | null>(null);
  const [recent, setRecent] = useState<readonly Recent[]>([]);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);

  const refresh = useCallback(() => {
    getHostStatus()
      .then(setStatus)
      .catch((error: unknown) => {
        // The card renders its loading state rather than a false one: claiming "not
        // accepting" when the answer is unknown would be a specific claim nobody made.
        onToast({
          kind: 'error',
          message: error instanceof Error ? error.message : 'Could not read this machine’s state.',
        });
      });
    listRecent()
      .then((entries) => {
        setRecent(entries);
      })
      .catch(() => {
        // A recent list that cannot be read is an empty one for rendering purposes.
        // It is not worth a toast: nothing the user did caused it and nothing they can
        // do here fixes it.
        setRecent([]);
      });
  }, [onToast]);

  useEffect(refresh, [refresh]);

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
          // Shown under the address field rather than as a toast. It is about the thing
          // the user is looking at, and a toast would disappear while they read it.
          setFailure(error instanceof Error ? error.message : 'That machine could not be reached.');
        })
        .finally(() => {
          setBusy(false);
        });
    },
    [onConnected, refresh],
  );

  return (
    <div className="flex h-full flex-col bg-(--color-page)">
      <header className="flex items-center gap-3 border-b border-(--color-border) px-4 py-2.5">
        <h1 className="min-w-0 flex-1 truncate text-sm font-semibold">Remote Control</h1>
        <IconButton icon={Settings} label="Settings" onClick={onOpenSettings} />
      </header>

      <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto p-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <ThisDeskCard status={status} />
          <RemoteDeskCard onConnect={connect} busy={busy} error={failure} />
        </div>

        <RecentList entries={recent} onConnect={connect} busy={busy} />
      </div>
    </div>
  );
}
