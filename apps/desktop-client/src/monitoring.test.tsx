import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { metricsTickSchema, type MetricsTick, type Snapshot } from './api.js';
import {
  applyTick,
  diskUtilisation,
  MonitoringStrip,
  networkThroughput,
  toStripReading,
} from './MonitoringScreen.js';

/** A snapshot with a process list and static CPU identity, as one arrives from a fetch. */
function snapshot(): Snapshot {
  return {
    capturedAtMs: 1_000,
    uptimeSecs: 100,
    cpuModel: 'Test CPU @ 3.6GHz',
    cpuPercent: 10,
    cpuPerCore: [10, 10],
    logicalCores: 2,
    memoryUsedBytes: 4_000,
    memoryTotalBytes: 8_000,
    swapUsedBytes: 0,
    swapTotalBytes: 0,
    disks: [],
    networks: [],
    temperatures: [],
    topProcesses: [{ pid: 1, name: 'init', user: 'root', cpuPercent: 1, memoryBytes: 100 }],
    loadAverage: null,
  };
}

/** A pushed tick, carrying only what changes between samples. */
function tick(overrides: Partial<MetricsTick> = {}): MetricsTick {
  return {
    capturedAtMs: 2_000,
    uptimeSecs: 200,
    cpuPercent: 55,
    cpuPerCore: [50, 60],
    memoryUsedBytes: 6_000,
    memoryTotalBytes: 8_000,
    swapUsedBytes: 0,
    swapTotalBytes: 0,
    disks: [],
    networks: [],
    temperatures: [],
    loadAverage: null,
    ...overrides,
  };
}

describe('merging a pushed tick onto a snapshot', () => {
  it('replaces every reading the tick carries', () => {
    const merged = applyTick(snapshot(), tick());

    expect(merged.cpuPercent).toBe(55);
    expect(merged.cpuPerCore).toEqual([50, 60]);
    expect(merged.memoryUsedBytes).toBe(6_000);
    expect(merged.capturedAtMs).toBe(2_000);
    expect(merged.uptimeSecs).toBe(200);
  });

  it('keeps what a tick deliberately omits', () => {
    // Resending these every tick would cost a full process walk on the server and make
    // fixed facts look like live readings. They must survive the merge instead.
    const merged = applyTick(snapshot(), tick());

    expect(merged.cpuModel).toBe('Test CPU @ 3.6GHz');
    expect(merged.logicalCores).toBe(2);
    expect(merged.topProcesses).toHaveLength(1);
    expect(merged.topProcesses[0]?.name).toBe('init');
  });

  it('does not mutate the snapshot it was given', () => {
    // The screen holds the previous snapshot in state; mutating it would make React
    // skip the re-render that shows the new reading.
    const original = snapshot();
    applyTick(original, tick());

    expect(original.cpuPercent).toBe(10);
    expect(original.capturedAtMs).toBe(1_000);
  });

  it('carries an emptied disk list through rather than keeping a stale one', () => {
    // A volume that was unmounted must disappear, not linger because the tick was
    // empty. "Absent" is a real reading here.
    const withDisk = {
      ...snapshot(),
      disks: [{ mountPoint: '/data', filesystem: 'ext4', totalBytes: 10, availableBytes: 5 }],
    };

    expect(applyTick(withDisk, tick({ disks: [] })).disks).toEqual([]);
  });
});

describe('the tick schema', () => {
  it('rejects a payload that is missing a reading', () => {
    // The screen merges whatever parses; a partial tick would silently blank a figure.
    const { capturedAtMs, ...incomplete } = tick();
    expect(capturedAtMs).toBe(2_000);
    expect(metricsTickSchema.safeParse(incomplete).success).toBe(false);
  });

  it('accepts a tick with no load average, as Windows sends', () => {
    // Absent rather than three zeros: an operator cannot tell a missing reading from a
    // real zero, and will eventually trust the wrong one.
    const parsed = metricsTickSchema.safeParse(tick({ loadAverage: null }));
    expect(parsed.success).toBe(true);
  });
});

describe('reducing a real snapshot to the strip reading', () => {
  it('omits disk when the server reported no volumes', () => {
    const reading = toStripReading({ ...snapshot(), disks: [] });
    expect(reading.diskPercent).toBeUndefined();
  });

  it('computes disk usage as a percentage across every volume, not a flat 0', () => {
    const reading = toStripReading({
      ...snapshot(),
      disks: [
        { mountPoint: '/', filesystem: 'ext4', totalBytes: 100, availableBytes: 25 },
        { mountPoint: '/data', filesystem: 'ext4', totalBytes: 300, availableBytes: 100 },
      ],
    });
    // used = (100 - 25) + (300 - 100) = 275; total = 400; 275 / 400 * 100 = 68.75.
    // A swapped used/available, or a sum of percentages instead of bytes, would not
    // land on this exact figure.
    expect(reading.diskPercent).toBe(68.75);
  });

  it('omits network when the server reported no interfaces', () => {
    const reading = toStripReading({ ...snapshot(), networks: [] });
    expect(reading.networkRxBps).toBeUndefined();
    expect(reading.networkTxBps).toBeUndefined();
  });

  it('sums throughput across every interface, not just the first', () => {
    const reading = toStripReading({
      ...snapshot(),
      networks: [
        {
          interface: 'eth0',
          receiveRateBps: 1000,
          transmitRateBps: 200,
          receivedBytes: 0,
          transmittedBytes: 0,
        },
        {
          interface: 'wlan0',
          receiveRateBps: 500,
          transmitRateBps: 50,
          receivedBytes: 0,
          transmittedBytes: 0,
        },
      ],
    });
    expect(reading.networkRxBps).toBe(1500);
    expect(reading.networkTxBps).toBe(250);
  });

  it('omits memory when the server reported zero total memory', () => {
    // Zero total memory is a broken read, not a machine that genuinely has none — the
    // same "absent, not a fake zero" rule the disk and network cases apply.
    const reading = toStripReading({ ...snapshot(), memoryTotalBytes: 0 });
    expect(reading.memoryPercent).toBeUndefined();
  });

  it('computes memory usage as a percentage of total', () => {
    const reading = toStripReading({
      ...snapshot(),
      memoryUsedBytes: 3_000,
      memoryTotalBytes: 4_000,
    });
    expect(reading.memoryPercent).toBe(75);
  });
});

describe('the disk and network aggregation helpers directly', () => {
  it('diskUtilisation returns undefined for an empty disk list', () => {
    expect(diskUtilisation([])).toBeUndefined();
  });

  it('diskUtilisation weighs by bytes, not by volume count', () => {
    // A small, nearly-full volume and a large, nearly-empty one must not average as
    // if each volume counted equally — the figure is meant to read as "how full is
    // this machine's storage", which only bytes can answer.
    const percent = diskUtilisation([
      { mountPoint: '/small', filesystem: 'ext4', totalBytes: 10, availableBytes: 0 },
      { mountPoint: '/large', filesystem: 'ext4', totalBytes: 990, availableBytes: 990 },
    ]);
    // used = 10 + 0 = 10; total = 1000; 10 / 1000 * 100 = 1.
    expect(percent).toBe(1);
  });

  it('networkThroughput returns undefined for an empty interface list', () => {
    expect(networkThroughput([])).toBeUndefined();
  });

  it('networkThroughput keeps receive and transmit as separate sums', () => {
    const throughput = networkThroughput([
      {
        interface: 'eth0',
        receiveRateBps: 4_000,
        transmitRateBps: 100,
        receivedBytes: 0,
        transmittedBytes: 0,
      },
    ]);
    expect(throughput).toEqual({ rx: 4_000, tx: 100 });
  });
});

describe('the monitoring strip', () => {
  it('renders no process table', () => {
    render(<MonitoringStrip />);
    expect(screen.queryByRole('table')).toBeNull();
  });

  it('omits a reading the server could not measure rather than showing zero', () => {
    // An operator cannot tell a cold machine from a missing sensor if both read 0.
    render(<MonitoringStrip snapshot={{ cpuPercent: 12, memoryPercent: 44 }} />);
    expect(screen.getByText(/12/)).toBeInTheDocument();
    expect(screen.queryByText(/disk/i)).toBeNull();
  });
});
