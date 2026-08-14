/**
 * Surfaces.
 *
 * A card is a raised surface with a hairline border. It gains a hover treatment only
 * when it is genuinely interactive — a card that lights up under the pointer and then
 * does nothing when clicked is a broken affordance, so `interactive` is opt-in.
 */

import type { LucideIcon } from 'lucide-react';

export function Card({
  children,
  className = '',
  interactive = false,
  padded = true,
}: {
  readonly children: React.ReactNode;
  readonly className?: string | undefined;
  readonly interactive?: boolean | undefined;
  readonly padded?: boolean | undefined;
}): React.JSX.Element {
  return (
    <div
      className={
        'rounded-[var(--radius-card)] border border-(--color-border) bg-(--color-card) ' +
        'shadow-(--shadow-card) ' +
        (padded ? 'p-6 ' : '') +
        (interactive
          ? 'transition-[border-color,box-shadow,transform] duration-200 ease-(--ease-ui) hover:border-(--color-border-hover) '
          : '') +
        className
      }
    >
      {children}
    </div>
  );
}

/** A card's title row: an icon in a tinted well, a title, and optional trailing content. */
export function CardHeader({
  icon: Icon,
  title,
  trailing,
}: {
  readonly icon?: LucideIcon | undefined;
  readonly title: string;
  readonly trailing?: React.ReactNode | undefined;
}): React.JSX.Element {
  return (
    <div className="mb-3 flex items-center gap-2.5">
      {Icon !== undefined && (
        <span className="flex size-7 shrink-0 items-center justify-center rounded-lg bg-(--color-card) text-(--color-text-secondary)">
          <Icon aria-hidden="true" className="size-4" />
        </span>
      )}
      <h3 className="min-w-0 flex-1 truncate text-xl font-semibold tracking-tight">{title}</h3>
      {trailing}
    </div>
  );
}
