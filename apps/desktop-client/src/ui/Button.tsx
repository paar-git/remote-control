/**
 * Buttons.
 *
 * One component covers every textual action in the app so that focus, disabled and
 * pressed treatments cannot drift apart between screens. `IconButton` is the same
 * component with a square footprint and a mandatory label, because an icon with no
 * accessible name is an unlabelled control.
 */

import type { LucideIcon } from 'lucide-react';

import { Tooltip } from './Tooltip';

export type ButtonVariant = 'default' | 'primary' | 'danger' | 'ghost' | 'subtle';
export type ButtonSize = 'sm' | 'md';

/**
 * Shared by every variant.
 *
 * `active:translate-y-px` is the whole pressed state: enough to feel mechanical,
 * not enough to shift the layout around it.
 */
const BASE =
  'inline-flex select-none items-center justify-center gap-2 rounded-lg font-medium ' +
  'whitespace-nowrap transition-[background-color,border-color,color,opacity] duration-150 ' +
  'ease-(--ease-ui) active:translate-y-px disabled:pointer-events-none disabled:opacity-45 ' +
  'disabled:active:translate-y-0';

const VARIANTS: Record<ButtonVariant, string> = {
  default:
    'border border-(--color-border-strong) bg-(--color-surface-raised) text-(--color-text-primary) ' +
    'hover:border-(--color-text-muted) hover:bg-(--color-surface-overlay)',
  primary: 'bg-(--color-accent) text-(--color-accent-text) hover:bg-(--color-accent-hover)',
  danger:
    'border border-(--color-danger)/45 bg-(--color-danger-soft) text-(--color-danger) ' +
    'hover:border-(--color-danger) hover:bg-(--color-danger)/20',
  ghost:
    'text-(--color-text-secondary) hover:bg-(--color-surface-overlay) hover:text-(--color-text-primary)',
  subtle: 'bg-(--color-accent-soft) text-(--color-accent) hover:bg-(--color-accent)/25',
};

const SIZES: Record<ButtonSize, string> = {
  sm: 'h-7 px-2.5 text-xs',
  md: 'h-8 px-3 text-sm',
};

/** A labelled button with a consistent focus ring and disabled treatment. */
export function Button({
  children,
  onClick,
  variant = 'default',
  size = 'md',
  disabled = false,
  title,
  type = 'button',
  icon: Icon,
  className = '',
}: {
  readonly children?: React.ReactNode | undefined;
  readonly onClick?: (() => void) | undefined;
  readonly variant?: ButtonVariant | undefined;
  readonly size?: ButtonSize | undefined;
  readonly disabled?: boolean | undefined;
  readonly title?: string | undefined;
  readonly type?: 'button' | 'submit' | undefined;
  readonly icon?: LucideIcon | undefined;
  readonly className?: string | undefined;
}): React.JSX.Element {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      title={title}
      className={`${BASE} ${SIZES[size]} ${VARIANTS[variant]} ${className}`}
    >
      {Icon !== undefined && (
        <Icon aria-hidden="true" className={size === 'sm' ? 'size-3.5' : 'size-4'} />
      )}
      {children}
    </button>
  );
}

/**
 * A square, icon-only button.
 *
 * `label` is required and becomes both the accessible name and the tooltip: an icon
 * alone never says what it does, to a screen reader or to a new operator.
 */
export function IconButton({
  icon: Icon,
  label,
  onClick,
  variant = 'ghost',
  size = 'md',
  disabled = false,
  active = false,
  tooltipSide = 'bottom',
}: {
  readonly icon: LucideIcon;
  readonly label: string;
  readonly onClick?: (() => void) | undefined;
  readonly variant?: ButtonVariant | undefined;
  readonly size?: ButtonSize | undefined;
  readonly disabled?: boolean | undefined;
  readonly active?: boolean | undefined;
  readonly tooltipSide?: 'top' | 'bottom' | 'right' | undefined;
}): React.JSX.Element {
  return (
    <Tooltip label={label} side={tooltipSide}>
      <button
        type="button"
        onClick={onClick}
        disabled={disabled}
        aria-label={label}
        aria-pressed={active ? true : undefined}
        className={
          `${BASE} ${size === 'sm' ? 'size-7' : 'size-8'} p-0 ` +
          (active ? 'bg-(--color-accent-soft) text-(--color-accent)' : VARIANTS[variant])
        }
      >
        <Icon aria-hidden="true" className={size === 'sm' ? 'size-3.5' : 'size-4'} />
      </button>
    </Tooltip>
  );
}
