/**
 * Desktop status strip: readiness on the left, transport on the right.
 */

import { Lock } from 'lucide-react';

import type { ConnectionState, HostStatus } from '../api.js';
import { isBusy, isConnected } from '../api.js';

export function BottomStatusBar({
  status,
  connection,
}: {
  readonly status: HostStatus | null;
  readonly connection: ConnectionState;
}): React.JSX.Element {
  const live = isConnected(connection);
  const pending = isBusy(connection);
  const ready = status?.accepting === true;

  let tone = 'bg-(--color-text-muted)';
  let label = 'Connections disabled';
  if (live) {
    tone = 'bg-(--color-success)';
    label = 'Connected';
  } else if (pending) {
    tone = 'bg-(--color-accent) animate-status-pulse';
    label = 'Connecting';
  } else if (ready) {
    tone = 'bg-(--color-success)';
    label = 'Ready';
  }

  return (
    <footer className="flex h-[56px] shrink-0 items-center justify-between border-t border-(--color-border) bg-(--color-page) px-[25px]">
      <p className="flex items-center gap-2 text-[13px] text-(--color-text-muted)">
        <span aria-hidden="true" className={`size-2 rounded-full ${tone}`} />
        <span role="status">{label}</span>
      </p>
      <p className="flex items-center gap-2 text-[13px] text-(--color-text-muted)">
        <Lock aria-hidden="true" className="size-4" />
        Secure connection
      </p>
    </footer>
  );
}
