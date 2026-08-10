/**
 * Tooltips.
 *
 * Rendered into `document.body` and positioned with fixed coordinates, so a tooltip on
 * an item inside a scrolling sidebar is never clipped by its container — the case that
 * matters most here, since the collapsed sidebar depends on tooltips for its labels.
 *
 * A tooltip is supplementary. It appears after a short delay on hover, immediately on
 * keyboard focus, and it never carries information that is not also available elsewhere.
 */

import { useCallback, useEffect, useId, useRef, useState } from 'react';
import { createPortal } from 'react-dom';

type Side = 'top' | 'bottom' | 'right';

/** Distance between the trigger and the tooltip, in pixels. */
const OFFSET = 8;
const OPEN_DELAY_MS = 350;

export function Tooltip({
  label,
  children,
  side = 'bottom',
  disabled = false,
}: {
  readonly label: React.ReactNode;
  readonly children: React.ReactNode;
  readonly side?: Side | undefined;
  /** Suppresses the tooltip without changing the markup around it. */
  readonly disabled?: boolean | undefined;
}): React.JSX.Element {
  const id = useId();
  const anchor = useRef<HTMLSpanElement | null>(null);
  const timer = useRef<number | undefined>(undefined);
  const [position, setPosition] = useState<{ x: number; y: number } | null>(null);

  const place = useCallback(() => {
    const element = anchor.current;
    if (element === null) return;
    const box = element.getBoundingClientRect();

    switch (side) {
      case 'right':
        setPosition({ x: box.right + OFFSET, y: box.top + box.height / 2 });
        break;
      case 'top':
        setPosition({ x: box.left + box.width / 2, y: box.top - OFFSET });
        break;
      case 'bottom':
        setPosition({ x: box.left + box.width / 2, y: box.bottom + OFFSET });
        break;
    }
  }, [side]);

  const hide = useCallback(() => {
    window.clearTimeout(timer.current);
    setPosition(null);
  }, []);

  const showAfterDelay = useCallback(() => {
    if (disabled) return;
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(place, OPEN_DELAY_MS);
  }, [disabled, place]);

  const showNow = useCallback(() => {
    if (disabled) return;
    window.clearTimeout(timer.current);
    place();
  }, [disabled, place]);

  // A tooltip anchored to an element that scrolled away would point at nothing, and one
  // left open when the window resizes would be mispositioned. Both are cheaper to
  // dismiss than to track.
  useEffect(() => {
    if (position === null) return;
    window.addEventListener('scroll', hide, true);
    window.addEventListener('resize', hide);
    return () => {
      window.removeEventListener('scroll', hide, true);
      window.removeEventListener('resize', hide);
    };
  }, [position, hide]);

  useEffect(
    () => () => {
      window.clearTimeout(timer.current);
    },
    [],
  );

  const transform =
    side === 'right'
      ? 'translate(0, -50%)'
      : side === 'top'
        ? 'translate(-50%, -100%)'
        : 'translate(-50%, 0)';

  return (
    <>
      <span
        ref={anchor}
        className="inline-flex"
        aria-describedby={position === null ? undefined : id}
        onPointerEnter={showAfterDelay}
        onPointerLeave={hide}
        onPointerDown={hide}
        onFocusCapture={showNow}
        onBlurCapture={hide}
      >
        {children}
      </span>

      {position !== null &&
        createPortal(
          <span
            id={id}
            role="tooltip"
            style={{ left: position.x, top: position.y, transform }}
            className="animate-fade-in pointer-events-none fixed z-100 max-w-64 rounded-md border border-(--color-border-strong) bg-(--color-surface-overlay) px-2 py-1 text-xs leading-snug text-(--color-text-primary) shadow-lg shadow-black/40"
          >
            {label}
          </span>,
          document.body,
        )}
    </>
  );
}
