/**
 * Surfaces.
 *
 * A card is a raised surface with a hairline border. It gains a hover treatment only
 * when it is genuinely interactive — a card that lights up under the pointer and then
 * does nothing when clicked is a broken affordance, so `interactive` is opt-in.
 */

import { Check, Copy, type LucideIcon } from 'lucide-react';
import { useState } from 'react';

import { Tooltip } from './Tooltip';

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
        'rounded-xl border border-(--color-border) bg-(--color-card) ' +
        (padded ? 'p-4 ' : '') +
        (interactive
          ? 'transition-colors duration-150 ease-(--ease-ui) hover:border-(--color-border) hover:bg-(--color-card) '
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
      <h3 className="min-w-0 flex-1 truncate text-sm font-semibold">{title}</h3>
      {trailing}
    </div>
  );
}

/**
 * A card whose body is a definition list of label/value rows.
 *
 * Rows are a `<dl>` rather than a table because this is a set of facts about one thing,
 * not a grid — it reflows to a single column in a narrow window without losing the
 * association between a label and its value.
 */
export function InfoCard({
  icon,
  title,
  trailing,
  children,
  footer,
}: {
  readonly icon?: LucideIcon | undefined;
  readonly title: string;
  readonly trailing?: React.ReactNode | undefined;
  readonly children: React.ReactNode;
  readonly footer?: React.ReactNode | undefined;
}): React.JSX.Element {
  return (
    <Card padded={false} className="flex flex-col">
      <div className="px-4 pt-4">
        <CardHeader icon={icon} title={title} trailing={trailing} />
      </div>
      <dl className="flex-1 px-4">{children}</dl>
      {footer !== undefined && (
        <div className="mt-1 border-t border-(--color-border) px-4 py-3">{footer}</div>
      )}
    </Card>
  );
}

/**
 * One label/value row inside an {@link InfoCard}.
 *
 * The value is selectable so it can be copied by hand, and `copyable` adds a button that
 * appears on hover or keyboard focus — visible on demand rather than a permanent column
 * of icons competing with the values themselves.
 */
export function InfoRow({
  label,
  value,
  mono = false,
  copyable,
  tone,
}: {
  readonly label: string;
  readonly value: React.ReactNode;
  /** Technical values only: ids, versions, addresses, paths. */
  readonly mono?: boolean | undefined;
  /** The exact text to place on the clipboard, if this row is worth copying. */
  readonly copyable?: string | undefined;
  /** Colours the value, for rows that are themselves a state. */
  readonly tone?: string | undefined;
}): React.JSX.Element {
  return (
    <div className="group flex min-h-11 items-center justify-between gap-4 border-b border-(--color-border) py-2 last:border-b-0">
      <dt className="shrink-0 text-sm text-(--color-text-secondary)">{label}</dt>
      <dd className="flex min-w-0 items-center gap-1.5">
        <span
          className={`truncate text-sm select-text ${mono ? 'font-mono text-xs' : ''} ${tone ?? ''}`}
        >
          {value}
        </span>
        {copyable !== undefined && <InlineCopy value={copyable} label={label} />}
      </dd>
    </div>
  );
}

/**
 * A copy affordance that stays out of the way.
 *
 * Transparent until the row is hovered or the button itself is focused, so keyboard
 * users can still reach it — `opacity-0` alone would leave a focused control invisible.
 */
export function InlineCopy({
  value,
  label,
}: {
  readonly value: string;
  readonly label: string;
}): React.JSX.Element {
  const [copied, setCopied] = useState(false);

  return (
    <Tooltip label={copied ? 'Copied' : `Copy ${label.toLowerCase()}`}>
      <button
        type="button"
        aria-label={`Copy ${label.toLowerCase()}`}
        onClick={() => {
          navigator.clipboard
            .writeText(value)
            .then(() => {
              setCopied(true);
              setTimeout(() => {
                setCopied(false);
              }, 1600);
            })
            .catch(() => {
              // Clipboard access can be refused; the value is selectable either way.
              setCopied(false);
            });
        }}
        className="flex size-6 shrink-0 items-center justify-center rounded-md text-(--color-text-secondary) opacity-0 transition-[opacity,color,background-color] duration-150 ease-(--ease-ui) group-hover:opacity-100 hover:bg-(--color-card) hover:text-(--color-text) focus-visible:opacity-100"
      >
        {copied ? (
          <Check aria-hidden="true" className="size-3.5 text-(--color-success)" />
        ) : (
          <Copy aria-hidden="true" className="size-3.5" />
        )}
      </button>
    </Tooltip>
  );
}
