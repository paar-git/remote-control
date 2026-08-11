/**
 * The status design system.
 *
 * Every state the app can be in resolves to one of six tones, and each tone has exactly
 * one colour, one dot treatment and one badge treatment. Screens map their own domain
 * state onto a tone; they never choose a colour directly. That is what stops "connected"
 * being green on one screen and blue on another.
 *
 * `busy` is the only animated tone, because it is the only one that means *wait*.
 */

import { Lock } from 'lucide-react';

export type StatusTone = 'ready' | 'busy' | 'warning' | 'danger' | 'idle' | 'unavailable';

interface ToneStyle {
  readonly dot: string;
  readonly badge: string;
}

const TONES: Record<StatusTone, ToneStyle> = {
  ready: {
    dot: 'bg-(--color-success)',
    badge: 'border-(--color-success)/35 bg-(--color-success-soft) text-(--color-success)',
  },
  busy: {
    dot: 'bg-(--color-accent) animate-status-pulse',
    badge: 'border-(--color-accent)/35 bg-(--color-accent-soft) text-(--color-accent)',
  },
  warning: {
    dot: 'bg-(--color-warning)',
    badge: 'border-(--color-warning)/35 bg-(--color-warning-soft) text-(--color-warning)',
  },
  danger: {
    dot: 'bg-(--color-danger)',
    badge: 'border-(--color-danger)/35 bg-(--color-danger-soft) text-(--color-danger)',
  },
  idle: {
    dot: 'bg-(--color-text-secondary)',
    badge: 'border-(--color-border) bg-(--color-card) text-(--color-text-secondary)',
  },
  unavailable: {
    dot: 'bg-(--color-text-secondary)/60',
    badge: 'border-(--color-border) bg-transparent text-(--color-text-secondary)',
  },
};

/**
 * A bare status dot.
 *
 * Decorative on its own — it is always accompanied by the text it qualifies, so it is
 * hidden from assistive technology rather than given a label the sighted user cannot see.
 */
export function StatusDot({
  tone,
  className = '',
}: {
  readonly tone: StatusTone;
  readonly className?: string | undefined;
}): React.JSX.Element {
  return (
    <span
      aria-hidden="true"
      className={`inline-flex size-2 shrink-0 items-center justify-center ${className}`}
    >
      <span className={`size-2 rounded-full ${TONES[tone].dot}`} />
    </span>
  );
}

/** A dot plus a label: the standard way to render a state inline. */
export function StatusBadge({
  tone,
  children,
  icon = true,
}: {
  readonly tone: StatusTone;
  readonly children: React.ReactNode;
  /** Set false for a text-only pill, e.g. a role label rather than a state. */
  readonly icon?: boolean | undefined;
}): React.JSX.Element {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-medium ${TONES[tone].badge}`}
    >
      {icon &&
        (tone === 'unavailable' ? (
          <Lock aria-hidden="true" className="size-3" />
        ) : (
          <StatusDot tone={tone} />
        ))}
      {children}
    </span>
  );
}

/**
 * A small pill for a fact rather than a state — a role, a count, a format.
 *
 * Kept separate from {@link StatusBadge} so that "Operator" never looks like a health
 * indicator.
 */
export function Badge({
  children,
  tone = 'neutral',
}: {
  readonly children: React.ReactNode;
  readonly tone?: 'neutral' | 'success' | 'danger' | 'warning' | 'accent' | undefined;
}): React.JSX.Element {
  const tones: Record<string, string> = {
    neutral: 'border-(--color-border) bg-(--color-card) text-(--color-text-secondary)',
    success: 'border-(--color-success)/35 bg-(--color-success-soft) text-(--color-success)',
    danger: 'border-(--color-danger)/35 bg-(--color-danger-soft) text-(--color-danger)',
    warning: 'border-(--color-warning)/35 bg-(--color-warning-soft) text-(--color-warning)',
    accent: 'border-(--color-accent)/35 bg-(--color-accent-soft) text-(--color-accent)',
  };
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium ${tones[tone] ?? ''}`}
    >
      {children}
    </span>
  );
}
