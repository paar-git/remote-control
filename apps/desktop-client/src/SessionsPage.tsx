/**
 * What is happening now, and what already happened.
 */

import { useCallback, useEffect, useState } from 'react';

import { listSessionHistory, type InboundSession, type SessionRecord } from './api.js';
import { Activity } from 'lucide-react';

import { formatDuration, formatRelative, humanise } from './format.js';
import { permissionLabel } from './labels.js';
import { Button, EmptyState, PageHeader, type Toast } from './ui';

const HISTORY_POLL_MS = 2000;

export function SessionsPage({
  inbound,
  onDisconnectInbound,
  onToast,
}: {
  readonly inbound: readonly InboundSession[];
  readonly onDisconnectInbound: (sessionId: string) => void;
  readonly onToast: (toast: Toast) => void;
}): React.JSX.Element {
  const [history, setHistory] = useState<readonly SessionRecord[] | null>(null);

  const refreshHistory = useCallback(() => {
    listSessionHistory()
      .then(setHistory)
      .catch((error: unknown) => {
        onToast({
          kind: 'error',
          message: error instanceof Error ? error.message : 'Could not load session history.',
        });
        setHistory((current) => current ?? []);
      });
  }, [onToast]);

  useEffect(() => {
    refreshHistory();
    const timer = window.setInterval(refreshHistory, HISTORY_POLL_MS);
    return () => {
      window.clearInterval(timer);
    };
  }, [refreshHistory, inbound]);

  const empty = history !== null && inbound.length === 0 && history.length === 0;

  return (
    <div className="w-full">
      <PageHeader
        title="Sessions"
        description="Who is connected now, and what has already happened."
      />

      {empty ? (
        <EmptyState
          icon={Activity}
          title="No sessions yet"
          body="Incoming and outgoing connections will be listed here."
        />
      ) : (
        <div className="flex flex-col gap-6">
          {inbound.length > 0 && (
            <section data-testid="active-sessions">
              <h2 className="mb-2 text-[17px] font-medium">Active Sessions</h2>
              <ul className="overflow-hidden rounded-[4px] border border-(--color-border) bg-(--color-card)">
                {inbound.map((session, index) => (
                  <li key={session.sessionId}>
                    {index > 0 && <div className="mx-4 h-px bg-(--color-separator)" />}
                    <div className="flex min-h-12 items-center gap-4 px-4 py-2.5">
                      <p className="min-w-[140px] flex-1 truncate text-[14px] font-medium">
                        {session.deviceName}
                      </p>
                      <p className="w-[88px] shrink-0 text-[13px] text-(--color-text-secondary)">
                        Incoming
                      </p>
                      <p className="w-[72px] shrink-0 text-[13px] text-(--color-text-secondary)">
                        Active
                      </p>
                      <p className="w-[72px] shrink-0 font-mono text-[13px] text-(--color-text-secondary)">
                        {formatDuration(Math.max(0, (Date.now() - session.startedMs) / 1000))}
                      </p>
                      <p className="flex min-w-0 flex-1 flex-wrap gap-x-2 truncate text-[13px] text-(--color-text-muted)">
                        {session.permissions.map((permission) => (
                          <span key={permission}>{permissionLabel(permission)}</span>
                        ))}
                      </p>
                      <Button
                        variant="danger"
                        size="sm"
                        onClick={() => onDisconnectInbound(session.sessionId)}
                      >
                        Disconnect
                      </Button>
                    </div>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {history !== null && history.length > 0 && (
            <section data-testid="recent-sessions">
              <h2 className="mb-2 text-[17px] font-medium">Recent Sessions</h2>
              <ul className="overflow-hidden rounded-[4px] border border-(--color-border) bg-(--color-card)">
                {history.map((record, index) => (
                  <li key={record.id}>
                    {index > 0 && <div className="mx-4 h-px bg-(--color-separator)" />}
                    <div className="flex min-h-12 items-center gap-4 px-4 py-2.5">
                      <p className="min-w-[140px] flex-1 truncate text-[14px] font-medium">
                        {record.deviceName}
                      </p>
                      <p className="w-[88px] shrink-0 text-[13px] text-(--color-text-secondary)">
                        {humanise(record.direction)}
                      </p>
                      <p className="w-[72px] shrink-0 text-[13px] text-(--color-text-secondary)">
                        {humanise(record.outcome)}
                      </p>
                      <p className="hidden w-[120px] shrink-0 text-[13px] text-(--color-text-muted) sm:block">
                        {formatRelative(record.startedMs)}
                      </p>
                      <p className="w-[72px] shrink-0 font-mono text-[13px] text-(--color-text-secondary)">
                        {record.endedMs === null
                          ? '—'
                          : formatDuration(Math.max(0, (record.endedMs - record.startedMs) / 1000))}
                      </p>
                      {record.endReason !== null && record.endReason !== '' && (
                        <p className="truncate text-[13px] text-(--color-text-muted)">
                          {humanise(record.endReason)}
                        </p>
                      )}
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
