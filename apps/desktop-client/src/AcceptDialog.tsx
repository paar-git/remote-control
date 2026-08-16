/**
 * Someone is asking to control this machine.
 *
 * Three answers, plus unattended behind a second step. Administrator is never offered
 * here: a permission that rewrites the trust database must not be reachable from the
 * control people click several times a day.
 *
 * Reject takes initial focus. Escape, timeout and closing the window all refuse.
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
  type TrustChoice,
} from './api.js';
import { formatDeviceId, formatFingerprintGroups } from './format.js';
import { GRANTABLE_PERMISSIONS, osLabel } from './labels.js';
import { Button, type Toast } from './ui';

export function AcceptDialog({ onToast }: { readonly onToast: (toast: Toast) => void }) {
  const [request, setRequest] = useState<AcceptRequest | null>(null);
  const [checked, setChecked] = useState<readonly Permission[]>([]);
  const [answering, setAnswering] = useState(false);
  const [trustStep, setTrustStep] = useState(false);
  const [unattended, setUnattended] = useState(false);
  const rejectRef = useRef<HTMLButtonElement | null>(null);

  const show = useCallback((next: AcceptRequest | null) => {
    setRequest(next);
    setTrustStep(false);
    setUnattended(false);
    setChecked(GRANTABLE_PERMISSIONS.map((permission) => permission.id));
  }, []);

  useEffect(() => {
    let cancelled = false;
    getPendingAcceptRequest()
      .then((pending) => {
        if (!cancelled && pending !== null) show(pending);
      })
      .catch(() => undefined);

    const stop = listenAcceptRequests(
      (incoming) => {
        if (!cancelled) show(incoming);
      },
      () => {
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

  useEffect(() => {
    if (request !== null) rejectRef.current?.focus();
  }, [request]);

  const refuse = useCallback(() => {
    if (request === null || answering) return;
    setAnswering(true);
    const done = (): void => {
      setRequest(null);
      setAnswering(false);
      setTrustStep(false);
    };
    dismissAcceptRequest(request.requestId).then(done, (error: unknown) => {
      onToast({
        kind: 'error',
        message: error instanceof Error ? error.message : 'That answer could not be delivered.',
      });
      done();
    });
  }, [request, answering, onToast]);

  const accept = useCallback(
    (trust: TrustChoice) => {
      if (request === null || answering) return;
      if (checked.length === 0) {
        refuse();
        return;
      }
      setAnswering(true);
      const done = (): void => {
        setRequest(null);
        setAnswering(false);
        setTrustStep(false);
      };
      answerAcceptRequest(request.requestId, [...checked], trust).then(done, (error: unknown) => {
        onToast({
          kind: 'error',
          message: error instanceof Error ? error.message : 'That answer could not be delivered.',
        });
        done();
      });
    },
    [request, answering, checked, onToast, refuse],
  );

  useEffect(() => {
    if (request === null) return;
    const onKey = (event: KeyboardEvent): void => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      refuse();
    };
    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('keydown', onKey);
    };
  }, [request, refuse]);

  if (request === null) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-6">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="accept-title"
        className="w-full max-w-md rounded-[4px] border border-(--color-border) bg-(--color-card) p-5"
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
          <Row label="Machine" value={request.machineName} />
          <Row label="Device ID" value={formatDeviceId(request.identityFingerprint)} />
          <Row label="System" value={osLabel(request.osFamily)} />
          <Row label="Address" value={request.address} mono />
          <div className="flex gap-2">
            <dt className="w-24 shrink-0 text-(--color-text-secondary)">Identity</dt>
            <dd
              data-testid="accept-fingerprint"
              className="min-w-0 flex-1 font-mono text-xs leading-relaxed break-all"
            >
              {formatFingerprintGroups(request.identityFingerprint)}
            </dd>
          </div>
        </dl>

        {request.trusted && (
          <p className="mb-3 text-sm font-medium text-(--color-text-secondary)">Trusted device</p>
        )}

        <fieldset className="mb-4">
          <legend className="mb-2 text-xs font-medium text-(--color-text-secondary)">
            They will be able to
          </legend>
          <div className="flex flex-col gap-1.5">
            {GRANTABLE_PERMISSIONS.map((permission) => (
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

        {trustStep ? (
          <div className="mb-4 rounded-[4px] border border-(--color-border) bg-(--color-page) p-3">
            <label className="flex items-start gap-2.5 text-sm">
              <input
                type="checkbox"
                className="mt-0.5 size-4 accent-(--color-accent)"
                checked={unattended}
                onChange={(event) => {
                  setUnattended(event.target.checked);
                }}
              />
              <span>
                <span className="block font-medium">Connect without approval</span>
                <span className="block text-(--color-text-secondary)">
                  This device will be able to connect with nobody at the keyboard.
                </span>
              </span>
            </label>
            <div className="mt-3 flex justify-end">
              <Button
                variant="primary"
                disabled={answering}
                onClick={() => {
                  accept(unattended ? 'remember_unattended' : 'remember');
                }}
              >
                Confirm
              </Button>
            </div>
          </div>
        ) : null}

        <p className="mb-3 text-xs text-(--color-text-secondary)">
          Accept Once lasts for this session only. Accept &amp; Trust remembers the device and still
          asks next time. Unattended access is a second step after that.
        </p>
        <div className="flex flex-wrap justify-end gap-2">
          <Button ref={rejectRef} variant="default" disabled={answering} onClick={refuse}>
            Reject
          </Button>
          <Button
            variant="primary"
            disabled={answering}
            onClick={() => {
              accept('once');
            }}
          >
            Accept Once
          </Button>
          <Button
            variant="subtle"
            disabled={answering}
            onClick={() => {
              setTrustStep(true);
            }}
          >
            Accept & Trust
          </Button>
        </div>
      </div>
    </div>
  );
}

function Row({
  label,
  value,
  mono = false,
}: {
  readonly label: string;
  readonly value: string;
  readonly mono?: boolean | undefined;
}): React.JSX.Element {
  return (
    <div className="flex gap-2">
      <dt className="w-24 shrink-0 text-(--color-text-secondary)">{label}</dt>
      <dd className={`min-w-0 flex-1 truncate ${mono ? 'font-mono text-xs' : 'font-medium'}`}>
        {value}
      </dd>
    </div>
  );
}
