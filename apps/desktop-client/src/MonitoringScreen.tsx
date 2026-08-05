/**
 * The Monitoring screen.
 *
 * Every figure here was measured by the agent on the server. Where a value could not
 * be measured — no temperature sensor, no load average on Windows — the section is
 * absent and says why, rather than showing a zero that would be indistinguishable from
 * a real reading of zero.
 *
 * The screen polls rather than subscribing. A subscription would push a snapshot every
 * interval whether or not anyone was looking at it; polling from the screen that
 * displays it means the cost on the server stops when the operator navigates away.
 */

import { useCallback, useEffect, useRef, useState } from 'react';

import { type ServerFacts, type Snapshot, getServerFacts, getSystemSnapshot } from './api.js';
import { Badge, Button, EmptyState } from './components';
import { formatBytes, formatDuration, formatRate, formatTimestamp } from './format.js';

/** How often a new snapshot is requested. */
const REFRESH_MS = 2000;

/** How many samples the sparklines keep. */
const HISTORY_LENGTH = 60;

type LoadState =
  | { readonly status: 'idle' }
  | { readonly status: 'loading' }
  | { readonly status: 'ready'; readonly snapshot: Snapshot; readonly facts: ServerFacts | null }
  | { readonly status: 'error'; readonly message: string };

export default function MonitoringScreen(): React.JSX.Element {
  const [state, setState] = useState<LoadState>({ status: 'loading' });
  const [live, setLive] = useState(true);

  // Kept in a ref rather than state: the history is appended to on every tick and
  // reading it during render is enough. Putting it in state would re-render twice per
  // sample for no visible difference.
  const cpuHistory = useRef<number[]>([]);
  const memoryHistory = useRef<number[]>([]);
  const facts = useRef<ServerFacts | null>(null);

  const refresh = useCallback(() => {
    getSystemSnapshot()
      .then((snapshot) => {
        cpuHistory.current = [...cpuHistory.current, snapshot.cpuPercent].slice(-HISTORY_LENGTH);
        const memoryPercent =
          snapshot.memoryTotalBytes === 0
            ? 0
            : (snapshot.memoryUsedBytes / snapshot.memoryTotalBytes) * 100;
        memoryHistory.current = [...memoryHistory.current, memoryPercent].slice(-HISTORY_LENGTH);

        setState({ status: 'ready', snapshot, facts: facts.current });
      })
      .catch((error: unknown) => {
        setState({
          status: 'error',
          message: error instanceof Error ? error.message : 'Could not read the server’s status.',
        });
      });
  }, []);

  // The host facts change rarely enough to fetch once per visit.
  useEffect(() => {
    getServerFacts()
      .then((loaded) => {
        facts.current = loaded;
      })
      .catch(() => {
        // Not fatal: the live readings are the point of this screen, and the static
        // facts are context. A failure here leaves that panel out.
      });
  }, []);

  useEffect(() => {
    refresh();
    if (!live) return;

    const timer = window.setInterval(refresh, REFRESH_MS);
    return () => {
      window.clearInterval(timer);
    };
  }, [live, refresh]);

  if (state.status === 'loading' || state.status === 'idle') {
    return (
      <p role="status" className="text-sm text-(--color-text-secondary)">
        Reading the server’s status…
      </p>
    );
  }

  if (state.status === 'error') {
    return (
      <div role="alert" className="max-w-prose rounded border border-(--color-danger) p-4 text-sm">
        <h2 className="mb-1 font-semibold text-(--color-danger)">Could not read the server</h2>
        <p className="mb-3 text-(--color-text-secondary)">{state.message}</p>
        <Button onClick={refresh}>Try again</Button>
      </div>
    );
  }

  const { snapshot } = state;
  const memoryPercent =
    snapshot.memoryTotalBytes === 0
      ? 0
      : (snapshot.memoryUsedBytes / snapshot.memoryTotalBytes) * 100;

  return (
    <section>
      <header className="mb-6 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold">Monitoring</h2>
          <p className="max-w-prose text-sm text-(--color-text-secondary)">
            Live readings from the server. Everything shown was measured; anything the server could
            not measure is left out rather than shown as zero.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge tone={live ? 'success' : 'neutral'}>{live ? 'Live' : 'Paused'}</Badge>
          <Button
            onClick={() => {
              setLive((current) => !current);
            }}
          >
            {live ? 'Pause' : 'Resume'}
          </Button>
        </div>
      </header>

      <div className="mb-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Metric
          label="CPU"
          value={`${snapshot.cpuPercent.toFixed(1)}%`}
          detail={snapshot.cpuModel}
          history={cpuHistory.current}
        />
        <Metric
          label="Memory"
          value={`${memoryPercent.toFixed(1)}%`}
          detail={`${formatBytes(snapshot.memoryUsedBytes)} of ${formatBytes(snapshot.memoryTotalBytes)}`}
          history={memoryHistory.current}
        />
        <Metric
          label="Uptime"
          value={formatDuration(snapshot.uptimeSecs)}
          detail={`${String(snapshot.logicalCores)} logical cores`}
          history={[]}
        />
        <Metric
          label="Swap"
          value={
            snapshot.swapTotalBytes === 0 ? 'None configured' : formatBytes(snapshot.swapUsedBytes)
          }
          detail={
            snapshot.swapTotalBytes === 0
              ? 'This server has no swap or page file'
              : `of ${formatBytes(snapshot.swapTotalBytes)}`
          }
          history={[]}
        />
      </div>

      <Panel title="Per-core utilisation">
        <div className="grid grid-cols-2 gap-x-6 gap-y-1.5 sm:grid-cols-4">
          {snapshot.cpuPerCore.map((percent, index) => (
            // A core's identity *is* its position — there is nothing else to key on,
            // and the list is a fixed length for the life of the machine.
            <div key={`core-${String(index)}`} className="flex items-center gap-2 text-xs">
              <span className="w-10 shrink-0 text-(--color-text-secondary)">#{index}</span>
              <Bar percent={percent} />
              <span className="w-11 shrink-0 text-right tabular-nums">{percent.toFixed(0)}%</span>
            </div>
          ))}
        </div>
      </Panel>

      <Panel title="Disks">
        {snapshot.disks.length === 0 ? (
          <p className="text-sm text-(--color-text-secondary)">
            The server reported no volumes it could measure.
          </p>
        ) : (
          <ul className="flex flex-col gap-2">
            {snapshot.disks.map((disk) => {
              const used = disk.totalBytes - disk.availableBytes;
              const percent = disk.totalBytes === 0 ? 0 : (used / disk.totalBytes) * 100;
              return (
                <li key={disk.mountPoint} className="text-xs">
                  <div className="mb-1 flex flex-wrap items-baseline justify-between gap-2">
                    <span className="font-medium">{disk.mountPoint}</span>
                    <span className="text-(--color-text-secondary)">
                      {formatBytes(disk.availableBytes)} free of {formatBytes(disk.totalBytes)}
                      {disk.filesystem === '' ? '' : ` · ${disk.filesystem}`}
                    </span>
                  </div>
                  <Bar percent={percent} warnAbove={90} />
                </li>
              );
            })}
          </ul>
        )}
      </Panel>

      <Panel title="Network">
        {snapshot.networks.length === 0 ? (
          <p className="text-sm text-(--color-text-secondary)">
            The server reported no network interfaces.
          </p>
        ) : (
          <table className="w-full text-left text-xs">
            <thead className="text-(--color-text-secondary)">
              <tr>
                <th scope="col" className="pb-1 font-medium">
                  Interface
                </th>
                <th scope="col" className="pb-1 text-right font-medium">
                  Down
                </th>
                <th scope="col" className="pb-1 text-right font-medium">
                  Up
                </th>
                <th scope="col" className="pb-1 text-right font-medium">
                  Total received
                </th>
              </tr>
            </thead>
            <tbody>
              {snapshot.networks.map((network) => (
                <tr key={network.interface}>
                  <td className="py-0.5 font-mono">{network.interface}</td>
                  <td className="py-0.5 text-right tabular-nums">
                    {formatRate(network.receiveRateBps)}
                  </td>
                  <td className="py-0.5 text-right tabular-nums">
                    {formatRate(network.transmitRateBps)}
                  </td>
                  <td className="py-0.5 text-right tabular-nums">
                    {formatBytes(network.receivedBytes)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      {snapshot.temperatures.length > 0 && (
        <Panel title="Temperatures">
          <ul className="grid gap-1 text-xs sm:grid-cols-2">
            {snapshot.temperatures.map((reading) => (
              <li key={reading.label} className="flex items-baseline justify-between gap-2">
                <span>{reading.label}</span>
                <span className="tabular-nums">
                  {reading.celsius.toFixed(1)} °C
                  {reading.criticalCelsius === null
                    ? ''
                    : ` (critical ${reading.criticalCelsius.toFixed(0)} °C)`}
                </span>
              </li>
            ))}
          </ul>
        </Panel>
      )}

      <Panel title="Busiest processes">
        {snapshot.topProcesses.length === 0 ? (
          <EmptyState
            title="No processes reported"
            body="The server did not return a process list."
          />
        ) : (
          <table className="w-full text-left text-xs">
            <thead className="text-(--color-text-secondary)">
              <tr>
                <th scope="col" className="pb-1 font-medium">
                  Name
                </th>
                <th scope="col" className="pb-1 font-medium">
                  PID
                </th>
                <th scope="col" className="pb-1 font-medium">
                  User
                </th>
                <th scope="col" className="pb-1 text-right font-medium">
                  CPU
                </th>
                <th scope="col" className="pb-1 text-right font-medium">
                  Memory
                </th>
              </tr>
            </thead>
            <tbody>
              {snapshot.topProcesses.map((process) => (
                <tr key={process.pid}>
                  <td className="py-0.5">{process.name}</td>
                  <td className="py-0.5 tabular-nums">{process.pid}</td>
                  <td className="py-0.5 text-(--color-text-secondary)">
                    {process.user ?? 'unknown'}
                  </td>
                  <td className="py-0.5 text-right tabular-nums">
                    {process.cpuPercent.toFixed(1)}%
                  </td>
                  <td className="py-0.5 text-right tabular-nums">
                    {formatBytes(process.memoryBytes)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      {state.facts !== null && (
        <Panel title="Server">
          <dl className="grid gap-x-6 gap-y-1 text-xs sm:grid-cols-[max-content_1fr]">
            <dt className="text-(--color-text-secondary)">Hostname</dt>
            <dd>{state.facts.hostname}</dd>

            <dt className="text-(--color-text-secondary)">Operating system</dt>
            <dd>
              {state.facts.osVersion} · kernel {state.facts.kernelVersion}
            </dd>

            <dt className="text-(--color-text-secondary)">Architecture</dt>
            <dd>{state.facts.architecture}</dd>

            <dt className="text-(--color-text-secondary)">Agent</dt>
            <dd>
              version {state.facts.agentVersion}, running as {state.facts.agentUser}
              {state.facts.agentElevated ? ' (elevated)' : ''}
            </dd>

            <dt className="text-(--color-text-secondary)">Last booted</dt>
            <dd>{formatTimestamp(state.facts.bootedAtMs)}</dd>
          </dl>
        </Panel>
      )}

      <p className="mt-4 text-xs text-(--color-text-secondary)">
        Last reading {formatTimestamp(snapshot.capturedAtMs)}
        {snapshot.loadAverage === null
          ? ' · this platform has no load average'
          : ` · load ${snapshot.loadAverage.map((value) => value.toFixed(2)).join(' ')}`}
      </p>
    </section>
  );
}

/** One headline figure, with a sparkline when there is history for it. */
function Metric({
  label,
  value,
  detail,
  history,
}: {
  readonly label: string;
  readonly value: string;
  readonly detail: string;
  readonly history: readonly number[];
}): React.JSX.Element {
  return (
    <div className="rounded border border-(--color-border-subtle) p-4">
      <div className="text-xs text-(--color-text-secondary)">{label}</div>
      <div className="mt-0.5 text-2xl font-semibold tabular-nums">{value}</div>
      <div className="mt-0.5 truncate text-xs text-(--color-text-secondary)" title={detail}>
        {detail}
      </div>
      {history.length > 1 && <Sparkline values={history} />}
    </div>
  );
}

/**
 * A sparkline over recent samples.
 *
 * Drawn against a fixed 0–100 scale rather than auto-scaling to the data. An
 * auto-scaled chart of an idle server makes noise look like load, which is exactly the
 * wrong impression for a monitoring screen to give.
 */
function Sparkline({ values }: { readonly values: readonly number[] }): React.JSX.Element {
  const width = 100;
  const height = 24;

  const points = values
    .map((value, index) => {
      const x = (index / Math.max(values.length - 1, 1)) * width;
      const y = height - (Math.min(Math.max(value, 0), 100) / 100) * height;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(' ');

  return (
    <svg
      viewBox={`0 0 ${String(width)} ${String(height)}`}
      preserveAspectRatio="none"
      className="mt-2 h-6 w-full"
      role="img"
      aria-label={`Recent history, currently ${values[values.length - 1]?.toFixed(0) ?? '0'} percent`}
    >
      <polyline
        points={points}
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        vectorEffect="non-scaling-stroke"
        className="text-(--color-accent)"
      />
    </svg>
  );
}

/** A proportion bar. */
function Bar({
  percent,
  warnAbove = 101,
}: {
  readonly percent: number;
  readonly warnAbove?: number;
}): React.JSX.Element {
  const clamped = Math.min(Math.max(percent, 0), 100);
  return (
    <div
      className="h-1.5 w-full overflow-hidden rounded-full bg-(--color-border-subtle)"
      role="img"
      aria-label={`${clamped.toFixed(0)} percent`}
    >
      <div
        className={`h-full rounded-full ${
          clamped >= warnAbove ? 'bg-(--color-danger)' : 'bg-(--color-accent)'
        }`}
        style={{ width: `${String(clamped)}%` }}
      />
    </div>
  );
}

/** A titled section. */
function Panel({
  title,
  children,
}: {
  readonly title: string;
  readonly children: React.ReactNode;
}): React.JSX.Element {
  return (
    <div className="mb-4 rounded border border-(--color-border-subtle) p-4">
      <h3 className="mb-3 text-sm font-semibold">{title}</h3>
      {children}
    </div>
  );
}
