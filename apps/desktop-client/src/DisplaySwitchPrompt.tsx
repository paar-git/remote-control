/**
 * The prompt shown the first time the pointer reaches a display boundary.
 *
 * # Why it asks at all, and why only once
 *
 * Switching display changes everything the operator can see, so doing it silently the
 * first time would be startling — they brushed an edge and the screen changed. But
 * asking *every* time would be worse than useless: crossing between monitors is
 * something you do constantly, and a dialog on each crossing would make multi-monitor
 * work unusable.
 *
 * So it asks once, and offers to stop asking. "Always switch" and "Never switch" are
 * both durable answers, saved and changeable later in Settings — a preference the
 * operator chose deliberately, not one inferred from their behaviour.
 *
 * # It never blocks
 *
 * This is not a modal. The session keeps running underneath it, the pointer keeps
 * working, and ignoring it leaves the operator on the display they were already on.
 * A prompt that trapped the session would be a worse failure than the one it prevents.
 */

import { ArrowRight } from 'lucide-react';

import type { RemoteDisplay, SwitchMode } from './displays';

export function DisplaySwitchPrompt({
  target,
  onDecide,
}: {
  /** The display the pointer is heading towards. */
  readonly target: RemoteDisplay;
  /**
   * `mode` is `null` for a one-off answer, or a durable preference to remember.
   * `move` is whether to switch right now.
   */
  readonly onDecide: (decision: { move: boolean; mode: SwitchMode | null }) => void;
}): React.JSX.Element {
  return (
    <div
      role="dialog"
      aria-label="Move to another display"
      className={
        'fixed bottom-6 left-1/2 z-50 flex -translate-x-1/2 flex-col gap-2 rounded-xl ' +
        'border border-(--color-border) bg-(--color-card) px-3 py-2.5 shadow-lg'
      }
    >
      <p className="flex items-center gap-2 text-sm text-(--color-text)">
        <ArrowRight aria-hidden="true" className="size-4 text-(--color-accent)" />
        Move to Display {target.index + 1}
        {target.primary && <span className="text-(--color-text-secondary)">· Main</span>}?
      </p>

      <div className="flex flex-wrap items-center gap-1.5">
        <Choice
          primary
          label="Move"
          onClick={() => {
            onDecide({ move: true, mode: null });
          }}
        />
        <Choice
          label="Stay"
          onClick={() => {
            onDecide({ move: false, mode: null });
          }}
        />
        <Choice
          label="Always switch"
          onClick={() => {
            onDecide({ move: true, mode: 'automatic' });
          }}
        />
        <Choice
          label="Don’t ask again"
          onClick={() => {
            // Declining durably means never switching from an edge — the operator can
            // still change display from the picker, which is not what they turned off.
            onDecide({ move: false, mode: 'never' });
          }}
        />
      </div>
    </div>
  );
}

function Choice({
  label,
  onClick,
  primary = false,
}: {
  readonly label: string;
  readonly onClick: () => void;
  readonly primary?: boolean;
}): React.JSX.Element {
  return (
    <button
      type="button"
      onClick={onClick}
      className={
        'rounded-lg px-2.5 py-1.5 text-xs font-medium transition-colors duration-150 ' +
        'ease-(--ease-ui) focus-visible:outline-2 focus-visible:outline-offset-2 ' +
        'focus-visible:outline-(--color-accent) ' +
        (primary
          ? 'bg-(--color-accent) text-white hover:opacity-90'
          : 'text-(--color-text-secondary) hover:bg-(--color-hover)')
      }
    >
      {label}
    </button>
  );
}
