/**
 * Someone is controlling this machine. Must never be invisible to the person sitting at it.
 */

import type { InboundSession } from './api.js';
import { formatDuration } from './format.js';
import { Button } from './ui';

export function InboundSessionBanner({
  sessions,
  onDisconnect,
  onEmergency,
}: {
  readonly sessions: readonly InboundSession[];
  readonly onDisconnect: (sessionId: string) => void;
  readonly onEmergency: () => void;
}): React.JSX.Element | null {
  if (sessions.length === 0) return null;

  return (
    <div
      role="status"
      className="flex flex-wrap items-center gap-3 border-b border-(--color-danger)/30 bg-(--color-danger-soft) px-4 py-2"
    >
      <div className="flex min-w-0 flex-1 flex-wrap items-center gap-3">
        {sessions.map((session) => (
          <div key={session.sessionId} className="flex min-w-0 flex-wrap items-center gap-2">
            <p className="min-w-0 text-sm">
              <span className="font-medium">{session.deviceName}</span>
              {' has been controlling this machine for '}
              {formatDuration(Math.max(0, (Date.now() - session.startedMs) / 1000))}.
            </p>
            <Button variant="ghost" size="sm" onClick={() => onDisconnect(session.sessionId)}>
              Disconnect
            </Button>
          </div>
        ))}
      </div>
      <Button variant="danger" size="sm" onClick={onEmergency}>
        Emergency Disconnect
      </Button>
    </div>
  );
}
