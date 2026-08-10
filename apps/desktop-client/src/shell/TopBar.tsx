/**
 * The application toolbar.
 *
 * Carries the two facts that matter everywhere and belong on no single screen: which
 * section is open, and whether there is a live session. The connection indicator is the
 * same component and the same polled state the Devices screen uses, so the two can never
 * disagree.
 */

import { Bell, Monitor } from 'lucide-react';

import { type ConnectionState, describeConnectionState } from '../api.js';
import { connectionLabel, connectionTone } from '../useConnection.js';
import { Button, IconButton, StatusBadge, Tooltip } from '../ui';
import { findNavItem } from './navigation';

export function TopBar({
  section,
  connection,
  pendingVersion,
  onOpenUpdates,
  onResumeSession,
}: {
  readonly section: string;
  readonly connection: ConnectionState;
  readonly pendingVersion: string | null;
  readonly onOpenUpdates: () => void;
  /** Present only while a session is open behind the current screen. */
  readonly onResumeSession?: (() => void) | undefined;
}): React.JSX.Element {
  const item = findNavItem(section);
  const Icon = item?.icon;

  return (
    <div className="flex h-14 shrink-0 items-center justify-between gap-4 border-b border-(--color-border-subtle) bg-(--color-surface) px-5">
      <div className="flex min-w-0 items-center gap-2 text-(--color-text-secondary)">
        {Icon !== undefined && <Icon aria-hidden="true" className="size-4 shrink-0" />}
        <span className="truncate text-sm font-medium text-(--color-text-primary)">
          {item?.label ?? 'Remote Control'}
        </span>
      </div>

      <div className="flex shrink-0 items-center gap-2">
        {/* The way back into a session the operator stepped out of. Only rendered when
            there is genuinely one open. */}
        {onResumeSession !== undefined && (
          <Button size="sm" icon={Monitor} onClick={onResumeSession}>
            Return to session
          </Button>
        )}

        <Tooltip label={describeConnectionState(connection)}>
          <span>
            <StatusBadge tone={connectionTone(connection)}>
              {connectionLabel(connection)}
            </StatusBadge>
          </span>
        </Tooltip>

        {pendingVersion !== null && (
          <span className="relative flex">
            <IconButton
              icon={Bell}
              label={`Version ${pendingVersion} is available`}
              onClick={onOpenUpdates}
            />
            <span
              aria-hidden="true"
              className="pointer-events-none absolute top-1 right-1 size-1.5 rounded-full bg-(--color-accent) ring-2 ring-(--color-surface)"
            />
          </span>
        )}
      </div>
    </div>
  );
}
