/**
 * What is happening now, and what already happened.
 */

import { useCallback, useEffect, useState } from 'react';

import {
  disconnectInbound,
  listInboundSessions,
  listSessionHistory,
  type InboundSession,
  type SessionRecord,
} from './api.js';
import { formatDuration, formatRelative, humanise } from './format.js';
import { permissionLabel } from './labels.js';
import { Button, EmptyState, PageHeader, type Toast } from './ui';

const POLL_MS = 2000;

export function SessionsPage({
  onToast,
}: {
  readonly onToast: (toast: Toast) => void;
}): React.JSX.Element {
  const [inbound, setInbound] = useState<readonly InboundSession[] | null>(null);
  const [history, setHistory] = useState<readonly SessionRecord[] | null>(null);

  const refreshInbound = useCallback(() => {
    listInboundSessions()
      .then(setInbound)
      .catch(() => {
        setInbound((current) => current ?? []);
      });
  }, []);

  useEffect(() => {
    refreshInbound();
    const timer = window.setInterval(refreshInbound, POLL_MS);
    return () => {
      window.clearInterval(timer);
    };
  }, [refreshInbound]);

  useEffect(() => {
    listSessionHistory()
      .then(setHistory)
      .catch((error: unknown) => {
        onToast({
          kind: 'error',
          message: error instanceof Error ? error.message : 'Could not load session history.',
        });
        setHistory([]);
      });
  }, [onToast]);

  const disconnect = (sessionId: string): void => {
    disconnectInbound(sessionId)
      .then(() => {
        refreshInbound();
      })
      .catch((error: unknown) => {
        onToast({
          kind: 'error',
          message: error instanceof Error ? error.message : 'Could not disconnect that session.',
        });
      });
  };

  const empty =
    inbound !== null && history !== null && inbound.length === 0 && history.length === 0;

  return (
    <div className="mx-auto w-full max-w-3xl">
      <PageHeader
        title="Sessions"
        description="Who is connected now, and what has already happened."
      />

      {empty ? (
        <EmptyState
          title="No sessions yet"
          body="Incoming and outgoing connections will be listed here."
        />
      ) : (
        <div className="flex flex-col gap-8">
          {inbound !== null && inbound.length > 0 && (
            <section data-testid="active-sessions">
              <h2 className="mb-3 text-base font-semibold">Active Sessions</h2>
              <ul className="flex flex-col gap-3">
                {inbound.map((session) => (
                  <li
                    key={session.sessionId}
                    className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-(--color-border) bg-(--color-card) px-4 py-3"
                  >
                    <div className="min-w-0">
                      <p className="font-medium">{session.deviceName}</p>
                      <p className="flex flex-wrap items-center gap-x-2 text-xs text-(--color-text-secondary)">
                        <span>
                          {formatDuration(Math.max(0, (Date.now() - session.startedMs) / 1000))}
                        </span>
                        {session.permissions.map((permission) => (
                          <span key={permission}>{permissionLabel(permission)}</span>
                        ))}
                      </p>
                    </div>
                    <Button
                      variant="danger"
                      size="sm"
                      onClick={() => disconnect(session.sessionId)}
                    >
                      Disconnect
                    </Button>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {history !== null && history.length > 0 && (
            <section data-testid="recent-sessions">
              <h2 className="mb-3 text-base font-semibold">Recent Sessions</h2>
              <ul className="flex flex-col gap-2">
                {history.map((record) => (
                  <li
                    key={record.id}
                    className="flex items-center justify-between gap-3 rounded-xl border border-(--color-border) bg-(--color-card) px-4 py-3"
                  >
                    <div className="min-w-0">
                      <p className="font-medium">{record.deviceName}</p>
                      <p className="text-xs text-(--color-text-secondary)">
                        <span>{humanise(record.outcome)}</span>
                        {' · '}
                        {formatRelative(record.startedMs)}
                      </p>
                    </div>
                  </li>
                ))}
              </ul>
            </section>
          )}
        </div>
      )}
    </div>
  );
}
