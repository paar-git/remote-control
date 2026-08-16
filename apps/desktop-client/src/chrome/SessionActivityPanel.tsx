/**
 * Last few sessions, incoming and outgoing, with real timestamps.
 */

import { ArrowDownLeft, ArrowUpRight } from 'lucide-react';

import type { SessionRecord } from '../api.js';
import { formatClockDuration, formatDayTime } from '../format.js';
import { Panel, PanelHeader, PanelSeeAll } from './Panel';

export function SessionActivityPanel({
  records,
  onViewAll,
}: {
  readonly records: readonly SessionRecord[];
  readonly onViewAll: () => void;
}): React.JSX.Element {
  const shown = records.slice(0, 2);

  return (
    <Panel testId="session-activity-panel">
      <PanelHeader
        title="Session activity"
        trailing={
          records.length > 0 ? <PanelSeeAll label="See all" onClick={onViewAll} /> : undefined
        }
      />
      {shown.length === 0 ? (
        <p className="px-[22px] pb-6 text-[13px] text-(--color-text-muted)">
          No session activity yet.
        </p>
      ) : (
        <ul>
          {shown.map((record, index) => {
            const incoming = record.direction === 'incoming';
            const duration =
              record.endedMs === null
                ? null
                : formatClockDuration(Math.max(0, (record.endedMs - record.startedMs) / 1000));
            return (
              <li key={record.id}>
                {index > 0 && <div className="mx-[22px] h-px bg-(--color-separator)" />}
                <div className="flex h-[72px] items-center gap-3 px-[22px] transition-colors duration-125 hover:bg-(--color-hover)">
                  <span
                    className={
                      'flex size-8 shrink-0 items-center justify-center rounded-[4px] ' +
                      (incoming
                        ? 'bg-(--color-success-soft) text-(--color-success)'
                        : 'bg-(--color-accent-soft) text-(--color-accent)')
                    }
                  >
                    {incoming ? (
                      <ArrowDownLeft aria-hidden="true" className="size-4" />
                    ) : (
                      <ArrowUpRight aria-hidden="true" className="size-4" />
                    )}
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-[15px] font-medium">{record.deviceName}</p>
                    <p className="text-[13px] text-(--color-text-muted)">
                      {incoming ? 'Incoming connection' : 'Outgoing connection'}
                    </p>
                  </div>
                  <div className="shrink-0 text-right">
                    <p className="text-[13px] text-(--color-text-muted)">
                      {formatDayTime(record.startedMs)}
                    </p>
                    {duration !== null && (
                      <p className="font-mono text-[13px] text-(--color-text-secondary)">
                        {duration}
                      </p>
                    )}
                  </div>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}
