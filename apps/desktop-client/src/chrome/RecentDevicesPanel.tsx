/**
 * Compact recent-device list with a real Connect action on each row.
 */

import type { Presence, Recent } from '../api.js';
import { DeviceAvatar } from '../DeviceAvatar';
import { formatDayTime } from '../format.js';
import { StatusBadge } from '../ui';
import { Panel, PanelHeader, PanelSeeAll } from './Panel';
import { SplitButton, SplitMenuItem } from './SplitButton';

export function RecentDevicesPanel({
  recent,
  presence,
  busy,
  onConnect,
  onViewAll,
}: {
  readonly recent: readonly Recent[];
  readonly presence: Readonly<Record<string, Presence>>;
  readonly busy: boolean;
  readonly onConnect: (address: string) => void;
  readonly onViewAll?: (() => void) | undefined;
}): React.JSX.Element {
  const shown = recent.slice(0, 2);

  return (
    <Panel testId="recent-devices-panel">
      <PanelHeader
        title="Recent devices"
        trailing={
          recent.length > 0 && onViewAll !== undefined ? (
            <PanelSeeAll label="See all" onClick={onViewAll} />
          ) : undefined
        }
      />
      {shown.length === 0 ? (
        <p className="px-[22px] pb-6 text-[13px] text-(--color-text-muted)">No recent devices.</p>
      ) : (
        <ul>
          {shown.map((entry, index) => (
            <li key={entry.address}>
              {index > 0 && <div className="mx-[22px] h-px bg-(--color-separator)" />}
              <div
                data-testid="recent-device"
                className="flex h-[88px] items-center gap-4 px-[22px] transition-colors duration-125 hover:bg-(--color-hover)"
              >
                <DeviceAvatar name={entry.machineName} size="lg" />
                <div className="min-w-0 flex-1">
                  <p className="truncate text-[15px] font-medium">{entry.machineName}</p>
                  <p className="truncate text-[13px] text-(--color-text-muted)">
                    Last connected: {formatDayTime(entry.lastConnectedMs)}
                  </p>
                </div>
                <RecentPresence presence={presence[entry.address] ?? 'checking'} />
                <SplitButton
                  label="Connect"
                  size="md"
                  variant="neutral"
                  disabled={busy}
                  onClick={() => {
                    onConnect(entry.address);
                  }}
                  menu={
                    <SplitMenuItem
                      onClick={() => {
                        onConnect(entry.address);
                      }}
                    >
                      Connect now
                    </SplitMenuItem>
                  }
                />
              </div>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

function RecentPresence({ presence }: { readonly presence: Presence }): React.JSX.Element {
  if (presence === 'checking') {
    return <StatusBadge tone="busy">Checking…</StatusBadge>;
  }
  if (presence === 'online') {
    return <StatusBadge tone="ready">Online</StatusBadge>;
  }
  return <StatusBadge tone="idle">Offline</StatusBadge>;
}
