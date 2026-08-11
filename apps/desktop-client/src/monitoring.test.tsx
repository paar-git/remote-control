import { describe, expect, it } from 'vitest';

import { metricsTickSchema, type MetricsTick, type Snapshot } from './api.js';
import { applyTick } from './MonitoringScreen.js';

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
