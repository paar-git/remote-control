/**
 * Someone is asking to control this machine.
 *
 * The one moment in this application where a person decides something that cannot be
 * undone by closing a window. Everything about it is arranged so that the *careless*
 * answer is the safe one.
 *
 * # Refusing is the default in every direction
 *
 * Dismiss takes initial focus, so a held Enter or a stray keystroke refuses. Escape
 * refuses. Closing the window refuses, because the backend's timeout does. There is no
 * way to accept without deliberately moving to the Accept button and pressing it.
 *
 * # There is no countdown
 *
 * The backend owns the thirty-second timeout. A second timer here would be a number on
 * screen that can disagree with the decision actually being made, and the disagreement
 * would show up exactly when it mattered.
 *
 * # An empty grant is refused, not accepted
 *
 * Unticking everything and pressing Accept sends a dismissal, not an accept of nothing.
 * The backend treats an empty grant as a refusal in one central place; sending an
 * accept here and relying on that would put the same rule in two places, and this way
 * the log records what the human meant.
 */

import { ShieldQuestion } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';

import {
  answerAcceptRequest,
  dismissAcceptRequest,
  getPendingAcceptRequest,
  listenAcceptRequests,
  type AcceptRequest,
  type Permission,
} from './api.js';
import { formatFingerprintGroups } from './format.js';
import { Button, type Toast } from './ui';

/** What each permission is called, in words about what the other person can do. */
const PERMISSIONS: readonly { readonly id: Permission; readonly label: string }[] = [
  { id: 'control_input', label: 'Control keyboard and mouse' },
  { id: 'transfer_files', label: 'Transfer files' },
  { id: 'view_metrics', label: 'View system information' },
];

export function AcceptDialog({ onToast }: { readonly onToast: (toast: Toast) => void }) {
  const [request, setRequest] = useState<AcceptRequest | null>(null);
  const [checked, setChecked] = useState<readonly Permission[]>([]);
  const [answering, setAnswering] = useState(false);
  const dismissRef = useRef<HTMLButtonElement | null>(null);

  const show = useCallback((next: AcceptRequest | null) => {
    setRequest(next);
    // Everything ticked when a request appears: the common case is a person who asked
    // you to connect, and the human's job here is to take away what they should not
    // have rather than to assemble a grant from nothing.
    setChecked(PERMISSIONS.map((permission) => permission.id));
  }, []);

  // Polled once on mount as well as driven by the event. An event emitted before this
  // component was listening reaches nobody, and the request would then sit unanswered
  // until it timed out with no dialog ever appearing.
  useEffect(() => {
    let cancelled = false;
    getPendingAcceptRequest()
      .then((pending) => {
        if (!cancelled && pending !== null) show(pending);
      })
      .catch(() => {
        // Nothing to show and nothing the user can do. The request times out and is
        // refused, which is the safe direction.
      });

    const stop = listenAcceptRequests(
      (incoming) => {
        if (!cancelled) show(incoming);
      },
      () => {
        // Withdrawn by the backend: it timed out, or the connection went away. The
        // dialog must go too, rather than inviting a click that would land on nothing.
        if (!cancelled) setRequest(null);
      },
    );

    return () => {
      cancelled = true;
      void stop.then((unlisten) => {
        unlisten();
      });
    };
  }, [show]);

  // Focus lands on Dismiss, not on the dialog. This is the assertion the whole design
  // rests on, so it is done explicitly rather than left to DOM order.
  useEffect(() => {
    if (request !== null) dismissRef.current?.focus();
  }, [request]);

  const answer = useCallback(
    (permissions: readonly Permission[]) => {
      if (request === null || answering) return;
      setAnswering(true);

      const done = (): void => {
        setRequest(null);
        setAnswering(false);
      };
      const failed = (error: unknown): void => {
        onToast({
          kind: 'error',
          message: error instanceof Error ? error.message : 'That answer could not be delivered.',
        });
        done();
      };

      if (permissions.length === 0) {
        dismissAcceptRequest(request.requestId).then(done, failed);
      } else {
        answerAcceptRequest(request.requestId, [...permissions]).then(done, failed);
      }
    },
    [request, answering, onToast],
  );

  useEffect(() => {
    if (request === null) return;
    const onKey = (event: KeyboardEvent): void => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      answer([]);
    };
    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('keydown', onKey);
    };
  }, [request, answer]);

  if (request === null) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-6">
      <div
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="accept-title"
        className="w-full max-w-md rounded-xl border border-(--color-border) bg-(--color-card) p-5 shadow-lg"
      >
        <div className="mb-3 flex items-center gap-2.5">
          <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-(--color-warning-soft) text-(--color-warning)">
            <ShieldQuestion aria-hidden="true" className="size-4" />
          </span>
          <h2 id="accept-title" className="text-base font-semibold">
            Allow this connection?
          </h2>
        </div>

        <dl className="mb-4 flex flex-col gap-2 text-sm">
          <div className="flex gap-2">
            <dt className="w-24 shrink-0 text-(--color-text-secondary)">Machine</dt>
            {/*
             * Interpolated as text, never as markup. React escapes it, and the schema
             * has already stripped the control characters and bidi overrides that would
             * let it render as a different name.
             */}
            <dd className="min-w-0 flex-1 truncate font-medium">{request.machineName}</dd>
          </div>
          <div className="flex gap-2">
            <dt className="w-24 shrink-0 text-(--color-text-secondary)">Address</dt>
            <dd className="min-w-0 flex-1 truncate font-mono text-xs">{request.address}</dd>
          </div>
          <div className="flex gap-2">
            <dt className="w-24 shrink-0 text-(--color-text-secondary)">Identity</dt>
            <dd
              data-testid="accept-fingerprint"
              className="min-w-0 flex-1 font-mono text-xs leading-relaxed break-all"
            >
              {formatFingerprintGroups(request.fingerprint)}
            </dd>
          </div>
        </dl>

        <fieldset className="mb-4">
          <legend className="mb-2 text-xs font-medium text-(--color-text-secondary)">
            They will be able to
          </legend>
          <div className="flex flex-col gap-1.5">
            {PERMISSIONS.map((permission) => (
              <label key={permission.id} className="flex items-center gap-2.5 text-sm">
                <input
                  type="checkbox"
                  className="size-4 accent-(--color-accent)"
                  checked={checked.includes(permission.id)}
                  onChange={(event) => {
                    setChecked((current) =>
                      event.target.checked
                        ? [...current, permission.id]
                        : current.filter((id) => id !== permission.id),
                    );
                  }}
                />
                {permission.label}
              </label>
            ))}
          </div>
        </fieldset>

        <div className="flex justify-end gap-2">
          {/* First in the DOM as well as focused, so Tab order agrees with intent. */}
          <Button
            ref={dismissRef}
            variant="default"
            disabled={answering}
            onClick={() => {
              answer([]);
            }}
          >
            Dismiss
          </Button>
          <Button
            variant="primary"
            disabled={answering}
            onClick={() => {
              answer(checked);
            }}
          >
            Accept
          </Button>
        </div>
      </div>
    </div>
  );
}
