/**
 * The session.
 *
 * Once you are connected, the interface gets out of the way: the window *is* the remote
 * machine, and the only chrome is a floating bar that hides itself. This is the part of
 * Chrome Remote Desktop worth copying most exactly.
 *
 * # The display area says what is true
 *
 * There is no screen capture and no input injection in this build. The area where the
 * remote screen will go therefore says so, in a sentence, and names what does work.
 *
 * It is deliberately *not* a dark rectangle with a spinner. That would be
 * indistinguishable from a session whose video had not arrived yet, and someone would
 * sit waiting for a picture that is not coming. An empty frame is a lie told by
 * omission; a sentence is not.
 *
 * # The tools are the session's permissions
 *
 * What the toolbar offers is decided by what the *other* machine granted, which arrives
 * on the connection state. A tool that was not granted is absent — see
 * {@link SessionToolbar} for why absent rather than disabled.
 */

import { MonitorOff, X } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';

import { disconnectFromServer, isConnected, pingServer, type ConnectionState } from './api.js';
import FilesScreen from './FilesScreen';
import MonitoringScreen from './MonitoringScreen';
import { SessionToolbar } from './SessionToolbar';
import { Button, type Toast } from './ui';
import { VideoSurface } from './VideoSurface';

/** How often the round trip to the machine is measured, in milliseconds. */
const PING_MS = 5000;

export function SessionScreen({
  connection,
  deviceName,
  permissions,
  onToast,
  onLeave,
}: {
  readonly connection: ConnectionState;
  /** The other machine's name, or `null` before it is known. */
  readonly deviceName: string | null;
  /** What the other machine granted this session. */
  readonly permissions: readonly string[];
  readonly onToast: (toast: Toast) => void;
  /** Return to the main window without ending the session. */
  readonly onLeave: () => void;
}): React.JSX.Element {
  const [latencyMs, setLatencyMs] = useState<number | null>(null);
  const [filesOpen, setFilesOpen] = useState(false);
  const [monitoringOpen, setMonitoringOpen] = useState(false);
  const [fitted, setFitted] = useState(true);
  const live = isConnected(connection);
  const canViewScreen = permissions.includes('view_screen');

  // Measured rather than assumed: this is the one number that says whether the link is
  // healthy, and it is cheap to obtain.
  useEffect(() => {
    if (!live) {
      setLatencyMs(null);
      return;
    }

    let cancelled = false;
    const measure = (): void => {
      pingServer()
        .then((ms) => {
          if (!cancelled) setLatencyMs(ms);
        })
        .catch(() => {
          // A failed ping is not worth a toast: the connection state is what tells the
          // user the link is gone, and it says so more accurately.
          if (!cancelled) setLatencyMs(null);
        });
    };

    measure();
    const timer = setInterval(measure, PING_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [live]);

  const disconnect = useCallback(() => {
    disconnectFromServer()
      .then(() => {
        onLeave();
      })
      .catch((error: unknown) => {
        onToast({
          kind: 'error',
          message:
            error instanceof Error ? error.message : 'The session could not be ended cleanly.',
        });
        // Left anyway: the user asked to go, and staying on a screen for a session
        // that may already be gone is worse than leaving one that may still be up.
        onLeave();
      });
  }, [onLeave, onToast]);

  return (
    <div className="relative flex h-full flex-col bg-(--color-page)">
      <SessionToolbar
        permissions={permissions}
        machineName={deviceName ?? 'Connected machine'}
        fitted={fitted}
        onToggleFitted={() => {
          setFitted((current) => !current);
        }}
        onDisconnect={disconnect}
        onOpenFiles={() => {
          setFilesOpen(true);
        }}
        onOpenMonitoring={() => {
          setMonitoringOpen((current) => !current);
        }}
      />

      <div className="min-h-0 flex-1">
        {canViewScreen ? (
          // Display 0: this build does not yet offer a picker for which of the
          // agent's displays to show, so the primary one is what a session opens on.
          <VideoSurface displayIndex={0} fitted={fitted} />
        ) : (
          <div className="flex h-full items-center justify-center p-6">
            <div className="max-w-md text-center">
              <span className="mx-auto mb-3 flex size-11 items-center justify-center rounded-2xl bg-(--color-card) text-(--color-text-secondary)">
                <MonitorOff aria-hidden="true" className="size-5" />
              </span>
              <p className="mb-1 text-sm font-medium">
                The other machine did not grant screen viewing.
              </p>
              <p className="text-sm text-(--color-text-secondary)">
                The session is live — the tools granted to it work from the bar above.
              </p>
              {latencyMs !== null && (
                <p className="mt-3 text-xs text-(--color-text-secondary)">
                  Round trip {latencyMs} ms
                </p>
              )}
            </div>
          </div>
        )}
      </div>

      {monitoringOpen && (
        <div className="border-t border-(--color-border) bg-(--color-card) px-4 py-3">
          <MonitoringScreen />
        </div>
      )}

      {filesOpen && (
        <div className="fixed inset-0 z-30 flex flex-col bg-(--color-page)">
          <header className="flex items-center gap-3 border-b border-(--color-border) px-4 py-2.5">
            <h2 className="min-w-0 flex-1 truncate text-sm font-semibold">Files</h2>
            <Button
              icon={X}
              variant="ghost"
              size="sm"
              onClick={() => {
                setFilesOpen(false);
              }}
            >
              Close
            </Button>
          </header>
          <div className="min-h-0 flex-1 overflow-auto">
            <FilesScreen onToast={onToast} />
          </div>
        </div>
      )}
    </div>
  );
}
