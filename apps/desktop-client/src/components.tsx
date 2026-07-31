/**
 * Shared presentational primitives.
 *
 * Deliberately small and unstyled-by-default: this is a dense administration tool, so
 * components carry structure and state semantics, not decoration.
 */

import { useEffect, useRef, useState } from 'react';

/** A labelled button with a consistent focus ring and disabled treatment. */
export function Button({
  children,
  onClick,
  variant = 'default',
  disabled = false,
  title,
  type = 'button',
}: {
  readonly children: React.ReactNode;
  readonly onClick?: () => void;
  readonly variant?: 'default' | 'primary' | 'danger' | 'ghost';
  readonly disabled?: boolean;
  readonly title?: string;
  readonly type?: 'button' | 'submit';
}): React.JSX.Element {
  const styles: Record<string, string> = {
    default:
      'border border-(--color-border-subtle) bg-(--color-surface-raised) hover:bg-(--color-surface-sunken)',
    primary: 'bg-(--color-accent) text-(--color-accent-text) hover:opacity-90',
    danger: 'border border-(--color-danger) text-(--color-danger) hover:bg-(--color-danger)/10',
    ghost: 'hover:bg-(--color-surface-sunken)',
  };

  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      title={title}
      className={`rounded px-3 py-1.5 text-sm font-medium transition-opacity disabled:cursor-not-allowed disabled:opacity-50 ${styles[variant] ?? ''}`}
    >
      {children}
    </button>
  );
}

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

  return (
    <div
      // `alert` for errors so screen readers interrupt; `status` for successes so
      // they do not.
      role={toast.kind === 'error' ? 'alert' : 'status'}
      className={`fixed right-6 bottom-6 max-w-sm rounded border px-4 py-2 text-sm shadow-lg ${
        toast.kind === 'error'
          ? 'border-(--color-danger) bg-(--color-surface-raised) text-(--color-danger)'
          : 'border-(--color-success) bg-(--color-surface-raised) text-(--color-success)'
      }`}
    >
      {toast.message}
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
  readonly destructive?: boolean;
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
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className="w-full max-w-md rounded border border-(--color-border-subtle) bg-(--color-surface-raised) p-5 shadow-xl"
      >
        <h2 className="mb-2 text-base font-semibold">{title}</h2>
        <div className="mb-5 text-sm text-(--color-text-secondary)">{body}</div>
        <div className="flex justify-end gap-2">
          {/* Cancel is focused first so pressing Enter reflexively does not destroy anything. */}
          <button
            ref={cancelRef}
            type="button"
            onClick={onCancel}
            className="rounded border border-(--color-border-subtle) px-3 py-1.5 text-sm font-medium hover:bg-(--color-surface-sunken)"
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

/** A copy-to-clipboard button that confirms it worked. */
export function CopyButton({
  value,
  label,
}: {
  readonly value: string;
  readonly label: string;
}): React.JSX.Element {
  const [copied, setCopied] = useState(false);

  return (
    <Button
      variant="ghost"
      title={`Copy ${label}`}
      onClick={() => {
        navigator.clipboard
          .writeText(value)
          .then(() => {
            setCopied(true);
            setTimeout(() => {
              setCopied(false);
            }, 2000);
          })
          .catch(() => {
            // Clipboard access can be refused; saying so beats failing silently.
            setCopied(false);
          });
      }}
    >
      {copied ? 'Copied' : 'Copy'}
    </Button>
  );
}

/** A labelled block for an empty list. */
export function EmptyState({
  title,
  body,
  action,
}: {
  readonly title: string;
  readonly body: string;
  readonly action?: React.ReactNode;
}): React.JSX.Element {
  return (
    <div className="rounded border border-dashed border-(--color-border-subtle) px-6 py-10 text-center">
      <p className="mb-1 text-sm font-medium">{title}</p>
      <p className="mx-auto mb-4 max-w-md text-sm text-(--color-text-secondary)">{body}</p>
      {action}
    </div>
  );
}

/** A small status pill. */
export function Badge({
  children,
  tone = 'neutral',
}: {
  readonly children: React.ReactNode;
  readonly tone?: 'neutral' | 'success' | 'danger' | 'warning';
}): React.JSX.Element {
  const tones: Record<string, string> = {
    neutral: 'border-(--color-border-subtle) text-(--color-text-secondary)',
    success: 'border-(--color-success) text-(--color-success)',
    danger: 'border-(--color-danger) text-(--color-danger)',
    warning: 'border-(--color-warning) text-(--color-warning)',
  };
  return (
    <span
      className={`rounded-full border px-2 py-0.5 text-[11px] font-medium ${tones[tone] ?? ''}`}
    >
      {children}
    </span>
  );
}
