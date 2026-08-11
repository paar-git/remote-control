/**
 * The session.
 *
 * Once you are connected, the interface gets out of the way: the window is the remote
 * computer, and the only permanent chrome is a small handle on the right edge. Opening it
 * slides out a narrow options panel; closing it leaves the viewport completely
 * uncovered. This is the part of Chrome Remote Desktop worth copying most exactly.
 *
 * # What is real here
 *
 * Disconnect, the round-trip measurement and the session tools are real operations
 * against the connected computer. The display, clipboard and input controls belong to a
 * remote-desktop pipeline this build does not have — there is no screen capture and no
 * input injection — so they are rendered in their unavailable state with the reason
 * attached rather than as switches that would flip and do nothing.
 */

import {
  ChevronRight,
  Clipboard,
  Folder,
  Keyboard,
  Maximize,
  Minimize,
  Monitor,
  MonitorOff,
  Activity as PulseIcon,
  Unplug,
  X,
} from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';

import { type ConnectionState, disconnectFromServer, isConnected, pingServer } from './api.js';
import { connectionLabel, connectionTone } from './useConnection.js';
import { Button, StatusDot, Tooltip, type Toast } from './ui';

/** How often the round trip to the computer is measured, in milliseconds. */
const PING_MS = 5000;

/** Why the display, clipboard and input controls cannot do anything yet. */
const NO_PIPELINE = 'Arrives with remote desktop';

export function SessionScreen({
  connection,
  deviceName,
  onToast,
  onLeave,
  onOpenTool,
}: {
  readonly connection: ConnectionState;
  readonly deviceName: string | null;
  readonly onToast: (toast: Toast) => void;
  /** Return to the device list without ending the session. */
  readonly onLeave: () => void;
  readonly onOpenTool: (section: string) => void;
}): React.JSX.Element {
  const [panelOpen, setPanelOpen] = useState(true);
  const [fullscreen, setFullscreen] = useState(false);
  const [latencyMs, setLatencyMs] = useState<number | null>(null);
  const live = isConnected(connection);

  // Measured rather than assumed: this is the one number that tells the operator
  // whether the link is healthy, and it is cheap to obtain.
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
          if (!cancelled) setLatencyMs(null);
        });
    };

    measure();
    const timer = window.setInterval(measure, PING_MS);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [live]);

  // The browser owns fullscreen state — it can also be left with F11 or Escape — so the
  // toggle reflects what actually happened rather than what it asked for.
  useEffect(() => {
    const sync = (): void => {
      setFullscreen(document.fullscreenElement !== null);
    };
    document.addEventListener('fullscreenchange', sync);
    return () => {
      document.removeEventListener('fullscreenchange', sync);
    };
  }, []);

  const toggleFullscreen = useCallback(() => {
    const request =
      document.fullscreenElement === null
        ? document.documentElement.requestFullscreen()
        : document.exitFullscreen();

    request.catch(() => {
      onToast({ kind: 'error', message: 'This window would not go full screen.' });
    });
  }, [onToast]);

  const disconnect = useCallback(() => {
    disconnectFromServer()
      .then(() => {
        onToast({ kind: 'success', message: 'Disconnected. It will not reconnect on its own.' });
        onLeave();
      })
      .catch((error: unknown) => {
        onToast({
          kind: 'error',
          message: error instanceof Error ? error.message : 'Could not disconnect.',
        });
      });
  }, [onLeave, onToast]);

  // Escape closes the panel rather than the session: an accidental Escape must never
  // drop a connection.
  useEffect(() => {
    const onKey = (event: KeyboardEvent): void => {
      if (event.key === 'Escape' && panelOpen) setPanelOpen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('keydown', onKey);
    };
  }, [panelOpen]);

  return (
    <div className="relative flex h-full overflow-hidden bg-black">
      <Viewport deviceName={deviceName} onOpenTool={onOpenTool} onLeave={onLeave} />

      {/* The handle. The only thing that permanently covers the remote computer, and it
          is 20 pixels wide. */}
      {!panelOpen && (
        <Tooltip label="Session options" side="top">
          <button
            type="button"
            onClick={() => {
              setPanelOpen(true);
            }}
            aria-label="Open session options"
            aria-expanded={false}
            className="absolute top-1/2 right-0 z-20 flex h-16 w-5 -translate-y-1/2 items-center justify-center rounded-l-lg border border-r-0 border-(--color-border-strong) bg-(--color-surface-raised)/90 text-(--color-text-secondary) backdrop-blur transition-colors duration-150 ease-(--ease-ui) hover:bg-(--color-surface-overlay) hover:text-(--color-text-primary)"
          >
            <ChevronRight aria-hidden="true" className="size-3.5 rotate-180" />
          </button>
        </Tooltip>
      )}

      <aside
        aria-label="Session options"
        aria-hidden={!panelOpen}
        className={`absolute inset-y-0 right-0 z-20 flex w-72 flex-col border-l border-(--color-border-subtle) bg-(--color-surface) transition-transform duration-200 ease-(--ease-ui) ${
          panelOpen ? 'translate-x-0' : 'pointer-events-none translate-x-full'
        }`}
      >
        <header className="flex items-start gap-2 border-b border-(--color-border-subtle) px-4 py-3">
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-semibold">{deviceName ?? 'Remote computer'}</p>
            <p className="mt-0.5 flex items-center gap-1.5 text-xs text-(--color-text-secondary)">
              <StatusDot tone={connectionTone(connection)} />
              {connectionLabel(connection)}
              {latencyMs !== null && (
                <span className="text-(--color-text-muted)">· {latencyMs} ms</span>
              )}
            </p>
          </div>
          <button
            type="button"
            onClick={() => {
              setPanelOpen(false);
            }}
            aria-label="Close session options"
            className="flex size-7 shrink-0 items-center justify-center rounded-lg text-(--color-text-muted) transition-colors duration-150 ease-(--ease-ui) hover:bg-(--color-surface-overlay) hover:text-(--color-text-primary)"
          >
            <X aria-hidden="true" className="size-4" />
          </button>
        </header>

        <div className="flex-1 overflow-y-auto px-3 py-3">
          <Button variant="danger" icon={Unplug} onClick={disconnect} className="h-9 w-full">
            Disconnect
          </Button>

          <PanelGroup label="Display">
            <PanelToggle
              icon={fullscreen ? Minimize : Maximize}
              label="Full screen"
              checked={fullscreen}
              onToggle={toggleFullscreen}
            />
            <PanelToggle icon={Monitor} label="Scale to fit" unavailable={NO_PIPELINE} />
            <PanelToggle icon={Monitor} label="Resize to window" unavailable={NO_PIPELINE} />
            <PanelToggle icon={Monitor} label="Smooth scaling" unavailable={NO_PIPELINE} />
          </PanelGroup>

          <PanelGroup label="Clipboard">
            <PanelToggle icon={Clipboard} label="Sync clipboard" unavailable={NO_PIPELINE} />
          </PanelGroup>

          <PanelGroup label="Input">
            <PanelAction icon={Keyboard} label="Ctrl+Alt+Del" unavailable={NO_PIPELINE} />
            <PanelAction icon={Keyboard} label="Print Screen" unavailable={NO_PIPELINE} />
          </PanelGroup>

          <PanelGroup label="Tools">
            <PanelAction
              icon={Folder}
              label="Files"
              onSelect={() => {
                onOpenTool('files');
              }}
            />
            <PanelAction
              icon={PulseIcon}
              label="Monitoring"
              onSelect={() => {
                onOpenTool('monitoring');
              }}
            />
          </PanelGroup>
        </div>

        <footer className="border-t border-(--color-border-subtle) px-3 py-2">
          <button
            type="button"
            onClick={onLeave}
            className="h-8 w-full rounded-lg text-sm text-(--color-text-secondary) transition-colors duration-150 ease-(--ease-ui) hover:bg-(--color-surface-overlay) hover:text-(--color-text-primary)"
          >
            Back to my computers
          </button>
        </footer>
      </aside>
    </div>
  );
}

/**
 * The remote computer's screen.
 *
 * There is no capture pipeline in this build, so rather than a black rectangle that
 * looks like a hung session, the viewport says what is happening and offers the parts of
 * the session that do work.
 */
function Viewport({
  deviceName,
  onOpenTool,
  onLeave,
}: {
  readonly deviceName: string | null;
  readonly onOpenTool: (section: string) => void;
  readonly onLeave: () => void;
}): React.JSX.Element {
  return (
    <div className="flex min-w-0 flex-1 items-center justify-center p-8">
      <div className="max-w-md text-center">
        <span className="mx-auto mb-4 flex size-14 items-center justify-center rounded-2xl border border-(--color-border-subtle) bg-(--color-surface-raised) text-(--color-text-muted)">
          <MonitorOff aria-hidden="true" className="size-6" />
        </span>
        <h2 className="text-base font-semibold text-(--color-text-primary)">
          The screen of {deviceName ?? 'this computer'} isn’t available yet
        </h2>
        <p className="mt-1.5 text-sm text-(--color-text-secondary)">
          You are connected and authenticated, but this version cannot show or control the remote
          screen. Everything else in the session works.
        </p>
        <div className="mt-5 flex flex-wrap justify-center gap-2">
          <Button
            variant="primary"
            icon={Folder}
            onClick={() => {
              onOpenTool('files');
            }}
          >
            Browse files
          </Button>
          <Button variant="ghost" onClick={onLeave}>
            Back to my computers
          </Button>
        </div>
      </div>
    </div>
  );
}

/** A labelled group of controls in the options panel. */
function PanelGroup({
  label,
  children,
}: {
  readonly label: string;
  readonly children: React.ReactNode;
}): React.JSX.Element {
  return (
    <section className="mt-5">
      <h3 className="mb-1 px-1 text-[10px] font-semibold tracking-[0.08em] text-(--color-text-muted) uppercase">
        {label}
      </h3>
      <div className="flex flex-col">{children}</div>
    </section>
  );
}

/** A checkbox row. Unavailable rows keep their label and say why they are inert. */
function PanelToggle({
  icon: Icon,
  label,
  checked = false,
  onToggle,
  unavailable,
}: {
  readonly icon: typeof Monitor;
  readonly label: string;
  readonly checked?: boolean | undefined;
  readonly onToggle?: (() => void) | undefined;
  readonly unavailable?: string | undefined;
}): React.JSX.Element {
  if (unavailable !== undefined) {
    return (
      <Tooltip label={unavailable} side="top">
        <span className="flex w-full cursor-not-allowed items-center gap-2.5 rounded-lg px-2 py-1.5 text-sm text-(--color-text-muted)">
          <Icon aria-hidden="true" className="size-4 shrink-0" />
          <span className="min-w-0 flex-1 truncate text-left">{label}</span>
          <span className="shrink-0 text-[10px]">Soon</span>
        </span>
      </Tooltip>
    );
  }

  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      onClick={onToggle}
      className="flex w-full items-center gap-2.5 rounded-lg px-2 py-1.5 text-sm text-(--color-text-secondary) transition-colors duration-150 ease-(--ease-ui) hover:bg-(--color-surface-overlay) hover:text-(--color-text-primary)"
    >
      <Icon aria-hidden="true" className="size-4 shrink-0" />
      <span className="min-w-0 flex-1 truncate text-left">{label}</span>
      <span
        aria-hidden="true"
        className={`flex h-4 w-7 shrink-0 items-center rounded-full p-0.5 transition-colors duration-150 ease-(--ease-ui) ${
          checked ? 'bg-(--color-accent)' : 'bg-(--color-surface-overlay)'
        }`}
      >
        <span
          className={`size-3 rounded-full bg-white transition-transform duration-150 ease-(--ease-ui) ${
            checked ? 'translate-x-3' : ''
          }`}
        />
      </span>
    </button>
  );
}

/** A command row. */
function PanelAction({
  icon: Icon,
  label,
  onSelect,
  unavailable,
}: {
  readonly icon: typeof Monitor;
  readonly label: string;
  readonly onSelect?: (() => void) | undefined;
  readonly unavailable?: string | undefined;
}): React.JSX.Element {
  if (unavailable !== undefined) {
    return (
      <Tooltip label={unavailable} side="top">
        <span className="flex w-full cursor-not-allowed items-center gap-2.5 rounded-lg px-2 py-1.5 text-sm text-(--color-text-muted)">
          <Icon aria-hidden="true" className="size-4 shrink-0" />
          <span className="min-w-0 flex-1 truncate text-left">{label}</span>
          <span className="shrink-0 text-[10px]">Soon</span>
        </span>
      </Tooltip>
    );
  }

  return (
    <button
      type="button"
      onClick={onSelect}
      className="flex w-full items-center gap-2.5 rounded-lg px-2 py-1.5 text-sm text-(--color-text-secondary) transition-colors duration-150 ease-(--ease-ui) hover:bg-(--color-surface-overlay) hover:text-(--color-text-primary)"
    >
      <Icon aria-hidden="true" className="size-4 shrink-0" />
      <span className="min-w-0 flex-1 truncate text-left">{label}</span>
    </button>
  );
}
