/**
 * The floating bar over a live session.
 *
 * # A tool you may not use is absent, not disabled
 *
 * The session's permissions were decided by the *other* machine, by a person clicking
 * Accept. Nothing on this side can change them, so a greyed-out Files button would say
 * "you could do this" and send the user looking for a setting that does not exist. The
 * honest rendering is that the tool is not there.
 *
 * Disconnect is the exception, and is always present: leaving is not a permission
 * somebody else grants you.
 *
 * # It gets out of the way, but never traps anyone
 *
 * The bar hides after {@link TOOLBAR_HIDE_MS} without pointer movement, because it is
 * floating over the thing you are actually looking at. It comes back when the pointer
 * nears the top edge — and only near the top edge, or working anywhere on the remote
 * screen would keep summoning it.
 *
 * It is visible on mount, so the way out is never hidden to begin with.
 *
 * Hiding is *visual only*. The bar keeps its place in the accessibility tree and stays
 * focusable, and focus brings it back into view. `aria-hidden` here would be a real
 * defect rather than a detail: someone driving this with a keyboard or a screen reader
 * does not generate pointer movement, so it would take Disconnect away from them for
 * the rest of the session with no way to get it back. `data-hidden` carries the state
 * for styling and for tests instead.
 */

import {
  FolderOpen,
  Gauge,
  Keyboard,
  LogOut,
  Maximize2,
  Scaling,
  type LucideIcon,
} from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';

/** How long without pointer movement before the bar gets out of the way. */
export const TOOLBAR_HIDE_MS = 3000;

/** How near the top edge the pointer must come to bring it back. */
export const TOOLBAR_REVEAL_PX = 80;

export function SessionToolbar({
  permissions,
  machineName,
  onDisconnect,
  onOpenFiles,
  onOpenMonitoring,
}: {
  /** What the other machine granted this session. */
  readonly permissions: readonly string[];
  /** Untrusted: chosen by the other machine. Rendered as text. */
  readonly machineName: string;
  readonly onDisconnect: () => void;
  readonly onOpenFiles: () => void;
  readonly onOpenMonitoring: () => void;
}): React.JSX.Element {
  const [visible, setVisible] = useState(true);
  const [fitted, setFitted] = useState(true);
  const [passthrough, setPassthrough] = useState(false);
  const hideAt = useRef<ReturnType<typeof setTimeout> | null>(null);

  const scheduleHide = useCallback(() => {
    if (hideAt.current !== null) clearTimeout(hideAt.current);
    hideAt.current = setTimeout(() => {
      setVisible(false);
    }, TOOLBAR_HIDE_MS);
  }, []);

  useEffect(() => {
    scheduleHide();

    const onMove = (event: MouseEvent): void => {
      if (event.clientY > TOOLBAR_REVEAL_PX) return;
      setVisible(true);
      scheduleHide();
    };

    window.addEventListener('mousemove', onMove);
    return () => {
      window.removeEventListener('mousemove', onMove);
      if (hideAt.current !== null) clearTimeout(hideAt.current);
    };
  }, [scheduleHide]);

  const may = (permission: string): boolean => permissions.includes(permission);

  return (
    <div
      role="toolbar"
      aria-label="Session tools"
      data-hidden={visible ? undefined : 'true'}
      className={
        'fixed top-3 left-1/2 z-40 flex -translate-x-1/2 items-center gap-1 rounded-xl ' +
        'border border-(--color-border) bg-(--color-card) px-1.5 py-1.5 shadow-lg ' +
        'transition-opacity duration-200 ease-(--ease-ui) ' +
        (visible ? 'opacity-100' : 'pointer-events-none opacity-0')
      }
      onMouseEnter={() => {
        // Reaching the bar must not let it vanish from under the pointer.
        if (hideAt.current !== null) clearTimeout(hideAt.current);
        setVisible(true);
      }}
      onMouseLeave={scheduleHide}
      onFocusCapture={() => {
        // Tabbing into the bar reveals it. This is what keeps it reachable without a
        // pointer, and it is why hiding is visual rather than `aria-hidden`.
        if (hideAt.current !== null) clearTimeout(hideAt.current);
        setVisible(true);
      }}
      onBlurCapture={scheduleHide}
    >
      <span className="max-w-40 truncate px-2 text-xs text-(--color-text-secondary)">
        {machineName}
      </span>

      <span aria-hidden="true" className="mx-0.5 h-5 w-px bg-(--color-border)" />

      {may('transfer_files') && <Tool icon={FolderOpen} label="Files" onClick={onOpenFiles} />}
      {may('view_metrics') && <Tool icon={Gauge} label="Monitoring" onClick={onOpenMonitoring} />}

      <Tool
        icon={Scaling}
        label="Fit to window"
        pressed={fitted}
        onClick={() => {
          setFitted((current) => !current);
        }}
      />
      <Tool
        icon={Keyboard}
        label="Keyboard passthrough"
        pressed={passthrough}
        onClick={() => {
          setPassthrough((current) => !current);
        }}
      />
      <Tool
        icon={Maximize2}
        label="Full screen"
        onClick={() => {
          // Best effort: the browser refuses outside a user gesture, and there is
          // nothing useful to say when it does.
          void document.documentElement.requestFullscreen?.().catch(() => undefined);
        }}
      />

      <span aria-hidden="true" className="mx-0.5 h-5 w-px bg-(--color-border)" />

      <button
        type="button"
        onClick={onDisconnect}
        className={
          'inline-flex items-center gap-1.5 rounded-lg bg-(--color-danger) px-2.5 py-1.5 ' +
          'text-xs font-medium text-white ' +
          'transition-colors duration-150 ease-(--ease-ui) hover:opacity-90 ' +
          'focus-visible:outline-2 focus-visible:outline-offset-2 ' +
          'focus-visible:outline-(--color-danger)'
        }
      >
        <LogOut aria-hidden="true" className="size-3.5" />
        Disconnect
      </button>
    </div>
  );
}

/** One icon control in the bar. The label is its accessible name and its tooltip. */
function Tool({
  icon: Icon,
  label,
  onClick,
  pressed,
}: {
  readonly icon: LucideIcon;
  readonly label: string;
  readonly onClick: () => void;
  readonly pressed?: boolean | undefined;
}): React.JSX.Element {
  return (
    <button
      type="button"
      title={label}
      aria-label={label}
      aria-pressed={pressed}
      onClick={onClick}
      className={
        'inline-flex size-8 items-center justify-center rounded-lg ' +
        'transition-colors duration-150 ease-(--ease-ui) hover:bg-(--color-hover) ' +
        'focus-visible:outline-2 focus-visible:outline-offset-2 ' +
        'focus-visible:outline-(--color-accent) ' +
        (pressed === true
          ? 'bg-(--color-hover) text-(--color-text)'
          : 'text-(--color-text-secondary)')
      }
    >
      <Icon aria-hidden="true" className="size-4" />
    </button>
  );
}
