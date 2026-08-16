/**
 * The session.
 *
 * Once you are connected, the interface gets out of the way: the window *is* the remote
 * machine, and the only chrome is a floating bar that hides itself. This is the part of
 * Chrome Remote Desktop worth copying most exactly.
 *
 * # The display area says what is true
 *
 * A session that was not granted screen viewing says so in a sentence, and names what
 * does work. It is deliberately *not* a dark rectangle with a spinner, which would be
 * indistinguishable from a session whose video had not arrived yet and would leave
 * someone waiting for a picture that is not coming. An empty frame is a lie told by
 * omission; a sentence is not.
 *
 * # This screen owns which monitor is being watched
 *
 * The host's arrangement lives here rather than in the surface, because three things
 * need it at once: the picker draws it, the edge-crossing rules navigate it, and the
 * surface streams one display out of it. It is refreshed by the host's own unsolicited
 * pushes, since a monitor plugged in mid-session moves where every later coordinate
 * lands.
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
import type { RemoteDisplay } from './displays';
import { DisplaySelector } from './DisplaySelector';
import { DisplaySwitchPrompt } from './DisplaySwitchPrompt';
import FilesScreen from './FilesScreen';
import { listenDisplays, sendPointerMove } from './inputApi.js';
import MonitoringScreen from './MonitoringScreen';
import { SessionToolbar } from './SessionToolbar';
import { Button, type Toast } from './ui';
import { useDisplayNavigation } from './useDisplayNavigation';
import { findDisplay } from './displays';
import { listDisplays } from './videoApi.js';
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
  // Off by default: translation is right for the shortcuts an operator uses all day,
  // and wrong only where a chord means something to a program rather than to the OS.
  const [passthrough, setPassthrough] = useState(false);
  const live = isConnected(connection);
  const canViewScreen = permissions.includes('view_screen');
  // Input is forwarded only where the other machine granted it. Capturing without the
  // grant would send every keystroke to a host that answers each one with a refusal.
  const canControl = permissions.includes('control_input');

  // The host's monitors: asked for once, then kept current by the host's own unsolicited
  // pushes, because a monitor plugged in mid-session moves where every later coordinate
  // lands.
  const [displays, setDisplays] = useState<readonly RemoteDisplay[]>([]);
  const [displaysOpen, setDisplaysOpen] = useState(false);
  const navigation = useDisplayNavigation(displays);

  useEffect(() => {
    if (!live || !canViewScreen) return undefined;

    let cancelled = false;
    let unlisten: (() => void) | undefined;

    listDisplays()
      .then((found) => {
        if (!cancelled) setDisplays(found);
      })
      // A host that will not enumerate its displays still streams display 0; a failed
      // list means no picker, not a broken session.
      .catch(() => undefined);

    listenDisplays((found) => {
      if (!cancelled) setDisplays(found);
    })
      .then((stop) => {
        if (cancelled) stop();
        else unlisten = stop;
      })
      .catch(() => undefined);

    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [live, canViewScreen]);

  // A picker for one monitor is chrome that can only pick what is already showing.
  const hasPicker = displays.length > 1;
  useEffect(() => {
    if (!hasPicker) setDisplaysOpen(false);
  }, [hasPicker]);

  const pendingTarget =
    navigation.pending === null
      ? null
      : findDisplay(displays, navigation.pending.crossing.display);

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
        passthrough={passthrough}
        onTogglePassthrough={() => {
          setPassthrough((current) => !current);
        }}
        hasDisplayPicker={hasPicker}
        displaysOpen={displaysOpen}
        onToggleDisplays={() => {
          setDisplaysOpen((current) => !current);
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
          <VideoSurface
            displayIndex={navigation.active}
            fitted={fitted}
            capturing={canControl}
            passthrough={passthrough}
            onPointerSample={navigation.onPointer}
          />
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

      {displaysOpen && hasPicker && (
        <div
          className={
            'fixed top-16 right-4 z-40 w-64 rounded-xl border border-(--color-border) ' +
            'bg-(--color-card) p-3 shadow-lg'
          }
        >
          <DisplaySelector
            displays={displays}
            active={navigation.active}
            onSelect={navigation.select}
          />
        </div>
      )}

      {/* Asked, not assumed: crossing an edge moves the view to another monitor, and an
          operator who did not mean it would rather say so than be moved. Answering also
          offers to remember, so the question stops being asked. */}
      {pendingTarget !== null && (
        <DisplaySwitchPrompt
          target={pendingTarget}
          onDecide={(decision) => {
            const crossing = navigation.decide(decision);
            if (crossing !== null) {
              void sendPointerMove(crossing.x, crossing.y, crossing.display).catch(() => undefined);
            }
          }}
        />
      )}

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
