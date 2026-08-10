/**
 * Feedback: toasts, confirmations, empty states, failures and loading placeholders.
 *
 * The rule these share is that the operator is told what happened in plain language
 * first. Raw errors are not hidden — they are put behind a disclosure, so the message
 * on screen stays readable while the detail needed to diagnose it is one click away.
 */

import { AlertTriangle, CheckCircle2, type LucideIcon } from 'lucide-react';
import { useEffect, useRef } from 'react';

import { Button } from './Button';

/** A short-lived status message. */
export interface Toast {
  readonly kind: 'success' | 'error';
  readonly message: string;
}

/** Renders a toast and clears it automatically. */
export function ToastBar({
  toast,
  onDismiss,
}: {
  readonly toast: Toast | null;
  readonly onDismiss: () => void;
}): React.JSX.Element | null {
  useEffect(() => {
    if (toast === null) return;
    const timer = setTimeout(onDismiss, 5000);
    return () => {
      clearTimeout(timer);
    };
  }, [toast, onDismiss]);

  if (toast === null) return null;

  const error = toast.kind === 'error';

  return (
    <div
      // `alert` for errors so screen readers interrupt; `status` for successes so
      // they do not.
      role={error ? 'alert' : 'status'}
      className={`animate-toast-in fixed right-5 bottom-5 z-50 flex max-w-sm items-start gap-2.5 rounded-xl border px-3.5 py-2.5 text-sm shadow-xl shadow-black/40 ${
        error
          ? 'border-(--color-danger)/40 bg-(--color-surface-overlay) text-(--color-text-primary)'
          : 'border-(--color-success)/40 bg-(--color-surface-overlay) text-(--color-text-primary)'
      }`}
    >
      {error ? (
        <AlertTriangle aria-hidden="true" className="mt-px size-4 shrink-0 text-(--color-danger)" />
      ) : (
        <CheckCircle2 aria-hidden="true" className="mt-px size-4 shrink-0 text-(--color-success)" />
      )}
      <span className="min-w-0 break-words">{toast.message}</span>
    </div>
  );
}

/**
 * A modal confirmation dialog.
 *
 * Used for destructive actions. The confirm button is never the default focus, and
 * Escape always cancels.
 */
export function ConfirmDialog({
  open,
  title,
  body,
  confirmLabel,
  destructive = false,
  onConfirm,
  onCancel,
}: {
  readonly open: boolean;
  readonly title: string;
  readonly body: React.ReactNode;
  readonly confirmLabel: string;
  readonly destructive?: boolean | undefined;
  readonly onConfirm: () => void;
  readonly onCancel: () => void;
}): React.JSX.Element | null {
  const cancelRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    cancelRef.current?.focus();

    const onKey = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') onCancel();
    };
    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('keydown', onKey);
    };
  }, [open, onCancel]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4 backdrop-blur-[2px]">
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className="animate-fade-in w-full max-w-md rounded-xl border border-(--color-border-strong) bg-(--color-surface-raised) p-5 shadow-2xl shadow-black/50"
      >
        <div className="mb-3 flex items-center gap-2.5">
          {destructive && (
            <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-(--color-danger-soft) text-(--color-danger)">
              <AlertTriangle aria-hidden="true" className="size-4" />
            </span>
          )}
          <h2 className="text-base font-semibold">{title}</h2>
        </div>
        <div className="mb-5 text-sm text-(--color-text-secondary)">{body}</div>
        <div className="flex justify-end gap-2">
          {/* Cancel is focused first so pressing Enter reflexively does not destroy anything. */}
          <button
            ref={cancelRef}
            type="button"
            onClick={onCancel}
            className="inline-flex h-8 items-center rounded-lg border border-(--color-border-strong) px-3 text-sm font-medium transition-colors duration-150 ease-(--ease-ui) hover:bg-(--color-surface-overlay)"
          >
            Cancel
          </button>
          <Button variant={destructive ? 'danger' : 'primary'} onClick={onConfirm}>
            {confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  );
}

/** A labelled block for an empty list. */
export function EmptyState({
  title,
  body,
  action,
  icon: Icon,
}: {
  readonly title: string;
  readonly body: string;
  readonly action?: React.ReactNode | undefined;
  readonly icon?: LucideIcon | undefined;
}): React.JSX.Element {
  return (
    <div className="flex flex-col items-center rounded-xl border border-dashed border-(--color-border-strong) px-6 py-10 text-center">
      {Icon !== undefined && (
        <span className="mb-3 flex size-10 items-center justify-center rounded-xl bg-(--color-surface-overlay) text-(--color-text-muted)">
          <Icon aria-hidden="true" className="size-5" />
        </span>
      )}
      <p className="mb-1 text-sm font-medium">{title}</p>
      <p className="mb-4 max-w-md text-sm text-(--color-text-secondary)">{body}</p>
      {action}
    </div>
  );
}

/**
 * A failure the operator can act on.
 *
 * `summary` is written for a person; `detail` is whatever the backend actually said and
 * is collapsed by default. Both matter — the first so the screen is usable, the second
 * so a report is possible.
 */
export function ErrorState({
  summary,
  detail,
  onRetry,
}: {
  readonly summary: string;
  readonly detail?: string | null | undefined;
  readonly onRetry?: (() => void) | undefined;
}): React.JSX.Element {
  return (
    <div
      role="alert"
      className="rounded-xl border border-(--color-danger)/40 bg-(--color-danger-soft) p-4"
    >
      <div className="flex items-start gap-2.5">
        <AlertTriangle
          aria-hidden="true"
          className="mt-0.5 size-4 shrink-0 text-(--color-danger)"
        />
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium">{summary}</p>
          {detail !== undefined && detail !== null && detail !== '' && (
            <details className="mt-2">
              <summary className="cursor-pointer text-xs text-(--color-text-secondary) hover:text-(--color-text-primary)">
                View technical details
              </summary>
              <p className="mt-1.5 rounded-md bg-black/25 p-2 font-mono text-xs break-words text-(--color-text-secondary) select-text">
                {detail}
              </p>
            </details>
          )}
          {onRetry !== undefined && (
            <div className="mt-3">
              <Button size="sm" onClick={onRetry}>
                Try again
              </Button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/** A placeholder with the shape of the content that is still loading. */
export function Skeleton({
  className = '',
}: {
  readonly className?: string | undefined;
}): React.JSX.Element {
  return (
    <span
      aria-hidden="true"
      className={`animate-skeleton block rounded-md bg-(--color-surface-raised) ${className}`}
    />
  );
}

/** Several skeleton rows shaped like an {@link InfoCard} body. */
export function SkeletonRows({
  rows = 4,
}: {
  readonly rows?: number | undefined;
}): React.JSX.Element {
  return (
    <div role="status" aria-label="Loading" className="flex flex-col gap-3">
      {Array.from({ length: rows }, (_, index) => (
        <div key={index} className="flex items-center justify-between gap-4">
          <Skeleton className="h-3 w-28" />
          <Skeleton className="h-3 w-20" />
        </div>
      ))}
    </div>
  );
}
