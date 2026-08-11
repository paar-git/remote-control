/**
 * The Monitoring screen: a compact strip, not a dashboard.
 *
 * Four figures — CPU, memory, disk and network — each measured by the agent on the
 * server. Where a value could not be measured, or a device the server did not report
 * (no volumes, no interfaces), that tile is absent rather than shown as zero: an
 * operator cannot tell a cold machine from a missing sensor if both read 0.
 *
 * # The screen subscribes, and falls back to polling
 *
 * The server pushes readings on the metrics channel, so a figure updates when the
 * server measures it rather than when this screen happens to ask. The subscription is
 * opened when the screen mounts and closed when it unmounts, so a dashboard nobody is
 * looking at costs the server nothing.
 *
 * If the subscription is refused — an older agent that does not implement it, or a
 * session that lost the capability — the screen polls instead. A dashboard that showed
 * nothing because a newer feature was unavailable would be worse than a slower one.
 *
 * # Ticks are merged onto a snapshot
 *
 * A tick carries only what changes: utilisation, memory, disks, network. The strip
 * itself only ever reads {@link StripReading}, a reduction of the full snapshot down to
 * the four figures it shows.
 */

import { Pause, Play } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';

import {
  type MetricsTick,
  type Snapshot,
  getSystemSnapshot,
  listenMetricsStopped,
  listenMetricsUpdate,
  subscribeMetrics,
  unsubscribeMetrics,
} from './api.js';
import { formatRate } from './format.js';
import { Button, Card, ErrorState, Skeleton, StatusBadge } from './ui';

/** How often readings are wanted, whether pushed or polled. */
const REFRESH_MS = 2000;

/** How many samples the sparklines keep. */
const HISTORY_LENGTH = 60;

/** How readings are currently arriving. */
type Delivery = 'push' | 'poll';

/**
 * Merge a pushed tick onto the snapshot the screen is showing.
 *
 * Everything a tick does not carry is kept from the snapshot.
 */
export function applyTick(snapshot: Snapshot, tick: MetricsTick): Snapshot {
  return {
    ...snapshot,
    capturedAtMs: tick.capturedAtMs,
    uptimeSecs: tick.uptimeSecs,
    cpuPercent: tick.cpuPercent,
    cpuPerCore: tick.cpuPerCore,
    memoryUsedBytes: tick.memoryUsedBytes,
    memoryTotalBytes: tick.memoryTotalBytes,
    swapUsedBytes: tick.swapUsedBytes,
    swapTotalBytes: tick.swapTotalBytes,
    disks: tick.disks,
    networks: tick.networks,
    temperatures: tick.temperatures,
    loadAverage: tick.loadAverage,
  };
}

/**
 * The four figures the strip shows, each present only when it could be measured.
 *
 * `networkRxBps` and `networkTxBps` are always present or absent together: they come
 * from the same set of interfaces, so a server with none reports neither.
 */
export interface StripReading {
  readonly cpuPercent?: number | undefined;
  readonly memoryPercent?: number | undefined;
  readonly diskPercent?: number | undefined;
  readonly networkRxBps?: number | undefined;
  readonly networkTxBps?: number | undefined;
}

/**
 * Aggregate disk usage across every volume the server reported, as one percentage.
 *
 * Exported so the reduction can be tested directly against real disk-list shapes,
 * rather than only through the component that happens to render its result.
 */
export function diskUtilisation(disks: Snapshot['disks']): number | undefined {
  if (disks.length === 0) return undefined;
  const totalBytes = disks.reduce((sum, disk) => sum + disk.totalBytes, 0);
  if (totalBytes === 0) return undefined;
  const usedBytes = disks.reduce((sum, disk) => sum + (disk.totalBytes - disk.availableBytes), 0);
  return (usedBytes / totalBytes) * 100;
}

/**
 * Aggregate throughput across every interface the server reported.
 *
 * Exported for the same reason as {@link diskUtilisation}.
 */
export function networkThroughput(
  networks: Snapshot['networks'],
): { readonly rx: number; readonly tx: number } | undefined {
  if (networks.length === 0) return undefined;
  return {
    rx: networks.reduce((sum, network) => sum + network.receiveRateBps, 0),
    tx: networks.reduce((sum, network) => sum + network.transmitRateBps, 0),
  };
}

/**
 * Reduce a full snapshot down to the four figures the strip shows.
 *
 * Exported so the whole reduction — the one place this task's "absent, never zero"
 * guarantee is actually decided — can be driven with real {@link Snapshot} inputs in
 * tests, not just with hand-built {@link StripReading} literals.
 */
export function toStripReading(snapshot: Snapshot): StripReading {
  const memoryPercent =
    snapshot.memoryTotalBytes === 0
      ? undefined
      : (snapshot.memoryUsedBytes / snapshot.memoryTotalBytes) * 100;
  const diskPercent = diskUtilisation(snapshot.disks);
  const network = networkThroughput(snapshot.networks);

  return {
    cpuPercent: snapshot.cpuPercent,
    ...(memoryPercent !== undefined && { memoryPercent }),
    ...(diskPercent !== undefined && { diskPercent }),
    ...(network !== undefined && { networkRxBps: network.rx, networkTxBps: network.tx }),
  };
}

type LoadState =
  | { readonly status: 'loading' }
  | { readonly status: 'ready'; readonly snapshot: Snapshot }
  | { readonly status: 'error'; readonly message: string };

export default function MonitoringScreen(): React.JSX.Element {
  const [state, setState] = useState<LoadState>({ status: 'loading' });
  const [live, setLive] = useState(true);
  const [delivery, setDelivery] = useState<Delivery>('poll');
  // The interval the server accepted, which may be slower than the one asked for. Shown
  // rather than the requested figure, so the badge states the rate actually being got.
  const [acceptedMs, setAcceptedMs] = useState<number | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  // Set when the server stops a stream for a reason other than this screen asking. It
  // re-runs the effect below down the polling path, so the notice saying readings are
  // being polled is true rather than aspirational.
  const [pushBlocked, setPushBlocked] = useState(false);

  // Kept in a ref rather than state: the history is appended to on every tick and
  // reading it during render is enough. Putting it in state would re-render twice per
  // sample for no visible difference.
  const cpuHistory = useRef<number[]>([]);
  const memoryHistory = useRef<number[]>([]);

  /** Append one reading to the sparkline histories. */
  const record = useCallback((cpuPercent: number, usedBytes: number, totalBytes: number) => {
    cpuHistory.current = [...cpuHistory.current, cpuPercent].slice(-HISTORY_LENGTH);
    const memoryPercent = totalBytes === 0 ? 0 : (usedBytes / totalBytes) * 100;
    memoryHistory.current = [...memoryHistory.current, memoryPercent].slice(-HISTORY_LENGTH);
  }, []);

  const refresh = useCallback(() => {
    getSystemSnapshot()
      .then((snapshot) => {
        record(snapshot.cpuPercent, snapshot.memoryUsedBytes, snapshot.memoryTotalBytes);
        setState({ status: 'ready', snapshot });
      })
      .catch((error: unknown) => {
        setState({
          status: 'error',
          message: error instanceof Error ? error.message : 'Could not read the server’s status.',
        });
      });
  }, [record]);

  /** Merge a pushed tick into whatever is on screen. */
  const applyPushedTick = useCallback(
    (tick: MetricsTick) => {
      record(tick.cpuPercent, tick.memoryUsedBytes, tick.memoryTotalBytes);
      setState((current) =>
        current.status === 'ready'
          ? { ...current, snapshot: applyTick(current.snapshot, tick) }
          : current,
      );
    },
    [record],
  );

  useEffect(() => {
    // One snapshot first, whichever way readings arrive afterwards: a tick carries no
    // disk or network figure until the first snapshot has something to merge onto.
    refresh();
    if (!live) return;

    let cancelled = false;
    const cleanups: (() => void)[] = [];

    /** Fall back to asking for a snapshot on a timer. */
    const poll = () => {
      setDelivery('poll');
      setAcceptedMs(null);
      const timer = window.setInterval(refresh, REFRESH_MS);
      cleanups.push(() => {
        window.clearInterval(timer);
      });
    };

    if (pushBlocked) {
      poll();
      return () => {
        cancelled = true;
        for (const cleanup of cleanups) cleanup();
      };
    }

    void (async () => {
      try {
        const accepted = await subscribeMetrics(REFRESH_MS);
        if (cancelled) {
          // Unmounted while the request was in flight. Stop the stream rather than
          // leaving the server sampling for a screen that is gone.
          void unsubscribeMetrics().catch(() => undefined);
          return;
        }

        cleanups.push(await listenMetricsUpdate(applyPushedTick));
        cleanups.push(
          await listenMetricsStopped((stopped) => {
            // Said out loud rather than letting the figures quietly stop moving: a
            // frozen dashboard that looks live is worse than one that says it stopped.
            if (stopped.reason !== 'unsubscribed') {
              setNotice(stopped.message);
              setPushBlocked(true);
            }
          }),
        );
        cleanups.push(() => {
          void unsubscribeMetrics().catch(() => undefined);
        });

        if (cancelled) return;
        setDelivery('push');
        setAcceptedMs(accepted);
        setNotice(null);
      } catch {
        // An agent that does not implement subscriptions, or a session that may not
        // watch. Polling still works, and a slower dashboard beats an empty one.
        if (cancelled) return;
        poll();
      }
    })();

    return () => {
      cancelled = true;
      for (const cleanup of cleanups) cleanup();
    };
  }, [live, refresh, applyPushedTick, pushBlocked]);

  if (state.status === 'loading') {
    return (
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {[0, 1, 2, 3].map((index) => (
          <Card key={index}>
            <Skeleton className="h-3 w-16" />
            <Skeleton className="mt-2 h-7 w-24" />
          </Card>
        ))}
      </div>
    );
  }

  if (state.status === 'error') {
    return (
      <ErrorState
        summary="The server’s readings couldn’t be collected."
        detail={state.message}
        onRetry={refresh}
      />
    );
  }

  return (
    <section className="animate-fade-in flex flex-col gap-3">
      <div className="flex items-center justify-between gap-3">
        <StatusBadge tone={live ? 'busy' : 'idle'}>
          {!live
            ? 'Paused'
            : delivery === 'push'
              ? `Live · pushed every ${((acceptedMs ?? REFRESH_MS) / 1000).toFixed(1)} s`
              : 'Live · polled'}
        </StatusBadge>
        <Button
          icon={live ? Pause : Play}
          size="sm"
          onClick={() => {
            setLive((current) => !current);
          }}
        >
          {live ? 'Pause' : 'Resume'}
        </Button>
      </div>

      {notice !== null && (
        <p
          role="status"
          className="rounded-xl border border-(--color-warning)/40 bg-(--color-warning-soft) p-3 text-sm text-(--color-text-secondary)"
        >
          {notice} These readings are being polled instead.
        </p>
      )}

      <MonitoringStrip
        snapshot={toStripReading(state.snapshot)}
        cpuHistory={cpuHistory.current}
        memoryHistory={memoryHistory.current}
      />
    </section>
  );
}

/**
 * The strip itself: CPU, memory, disk and network, each present only when it could be
 * measured. Purely presentational — it renders whatever {@link StripReading} it is
 * given and holds no subscription of its own, which is what makes it easy to test.
 */
export function MonitoringStrip({
  snapshot,
  cpuHistory = [],
  memoryHistory = [],
}: {
  readonly snapshot?: StripReading | undefined;
  readonly cpuHistory?: readonly number[] | undefined;
  readonly memoryHistory?: readonly number[] | undefined;
}): React.JSX.Element {
  const network =
    snapshot?.networkRxBps !== undefined && snapshot.networkTxBps !== undefined
      ? { rx: snapshot.networkRxBps, tx: snapshot.networkTxBps }
      : null;

  return (
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
      {snapshot?.cpuPercent !== undefined && (
        <MetricTile label="CPU" value={`${snapshot.cpuPercent.toFixed(1)}%`} history={cpuHistory} />
      )}
      {snapshot?.memoryPercent !== undefined && (
        <MetricTile
          label="Memory"
          value={`${snapshot.memoryPercent.toFixed(1)}%`}
          history={memoryHistory}
        />
      )}
      {snapshot?.diskPercent !== undefined && (
        <MetricTile label="Disk" value={`${snapshot.diskPercent.toFixed(1)}%`} history={[]} />
      )}
      {network !== null && (
        <MetricTile
          label="Network"
          value={`↓ ${formatRate(network.rx)} · ↑ ${formatRate(network.tx)}`}
          history={[]}
        />
      )}
    </div>
  );
}

/** One headline figure, with a sparkline when there is history for it. */
function MetricTile({
  label,
  value,
  history,
}: {
  readonly label: string;
  readonly value: string;
  readonly history: readonly number[];
}): React.JSX.Element {
  return (
    <Card>
      <div className="text-xs font-medium text-(--color-text-secondary)">{label}</div>
      <div className="mt-1 text-2xl font-semibold tracking-[-0.02em] tabular-nums">{value}</div>
      {history.length > 1 && <Sparkline values={history} />}
    </Card>
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
