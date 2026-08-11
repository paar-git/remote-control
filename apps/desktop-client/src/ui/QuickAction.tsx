/**
 * A quick action tile.
 *
 * An action that cannot be taken right now is still shown, still readable, and states
 * *why* — silently disabling it would leave the operator guessing whether the feature
 * exists. Only the available form is a `<button>`; the unavailable form is inert markup,
 * so it is neither focusable nor clickable.
 */

import type { LucideIcon } from 'lucide-react';

import { StatusBadge } from './Status';

export function QuickAction({
  icon: Icon,
  title,
  description,
  onSelect,
  unavailableReason,
}: {
  readonly icon: LucideIcon;
  readonly title: string;
  readonly description: string;
  readonly onSelect: () => void;
  /** When set, the tile is inert and this is shown in place of the description. */
  readonly unavailableReason?: string | undefined;
}): React.JSX.Element {
  const available = unavailableReason === undefined;

  const body = (
    <>
      <span
        className={`flex size-9 shrink-0 items-center justify-center rounded-lg transition-colors duration-150 ease-(--ease-ui) ${
          available
            ? 'bg-(--color-accent-soft) text-(--color-accent)'
            : 'bg-(--color-card) text-(--color-text-secondary)'
        }`}
      >
        <Icon aria-hidden="true" className="size-4.5" />
      </span>
      <span className="min-w-0 flex-1">
        <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <span
            className={`text-sm font-medium ${available ? '' : 'text-(--color-text-secondary)'}`}
          >
            {title}
          </span>
          {!available && (
            <span className="shrink-0">
              <StatusBadge tone="unavailable">Unavailable</StatusBadge>
            </span>
          )}
        </span>
        <span className="mt-1 block text-xs text-(--color-text-secondary)">
          {available ? description : unavailableReason}
        </span>
      </span>
    </>
  );

  if (!available) {
    return (
      <div
        aria-disabled="true"
        className="flex cursor-not-allowed items-start gap-3 rounded-xl border border-(--color-border) bg-(--color-card)/60 p-3.5 text-left"
      >
        {body}
      </div>
    );
  }

  return (
    <button
      type="button"
      onClick={onSelect}
      className="flex cursor-pointer items-start gap-3 rounded-xl border border-(--color-border) bg-(--color-card) p-3.5 text-left transition-[background-color,border-color] duration-150 ease-(--ease-ui) hover:border-(--color-border) hover:bg-(--color-card) active:translate-y-px"
    >
      {body}
    </button>
  );
}
