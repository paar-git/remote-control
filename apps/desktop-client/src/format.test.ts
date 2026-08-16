import { describe, expect, it } from 'vitest';

import {
  abbreviateFingerprint,
  compactDeviceId,
  formatDeviceId,
  formatFingerprintGroups,
  formatClockDuration,
  formatDayTime,
  formatRelative,
  formatTimestamp,
  humanise,
} from './format.js';

const FINGERPRINT = 'a'.repeat(64);

describe('device id', () => {
  it('groups nine stable digits from a fingerprint', () => {
    const id = formatDeviceId('a'.repeat(64));
    expect(id).toMatch(/^\d{3} \d{3} \d{3}$/);
    expect(formatDeviceId('a'.repeat(64))).toBe(id);
  });

  it('changes when the identity changes', () => {
    expect(formatDeviceId('a'.repeat(64))).not.toBe(formatDeviceId('b'.repeat(64)));
  });

  it('strips grouping spaces', () => {
    expect(compactDeviceId('842 391 552')).toBe('842391552');
  });

  it('does not invent an id from an empty value', () => {
    expect(formatDeviceId('')).toBe('—');
  });
});

describe('fingerprint formatting', () => {
  it('groups into sixteen blocks of four', () => {
    const formatted = formatFingerprintGroups(FINGERPRINT);
    expect(formatted.split(' ')).toHaveLength(16);
    expect(formatted.startsWith('AAAA AAAA')).toBe(true);
  });

  it('matches the Rust display form exactly', () => {
    // Both sides must render identically, or comparing two screens is useless.
    const hex = '0123456789abcdef'.repeat(4);
    expect(formatFingerprintGroups(hex).slice(0, 9)).toBe('0123 4567');
  });

  it('abbreviates long fingerprints keeping both ends', () => {
    const abbreviated = abbreviateFingerprint('0123456789abcdef'.repeat(4));
    expect(abbreviated).toContain('…');
    expect(abbreviated.startsWith('0123 4567')).toBe(true);
    expect(abbreviated.endsWith('89AB CDEF')).toBe(true);
  });

  it('leaves short values unabbreviated', () => {
    expect(abbreviateFingerprint('0123456789abcdef')).toBe('0123 4567 89AB CDEF');
  });
});

describe('timestamps', () => {
  it('renders a dash when absent', () => {
    expect(formatTimestamp(null)).toBe('—');
  });

  it('renders a real date', () => {
    expect(formatTimestamp(1_700_000_000_000)).not.toBe('—');
    expect(formatTimestamp(1_700_000_000_000).length).toBeGreaterThan(5);
  });

  it('reports never for an absent relative time', () => {
    expect(formatRelative(null)).toBe('Never');
  });

  it('reports recent times as just now', () => {
    const now = 1_700_000_000_000;
    expect(formatRelative(now - 5_000, now)).toBe('Just now');
  });

  it('formats a clock duration with tabular hours', () => {
    expect(formatClockDuration(381)).toBe('00:06:21');
    expect(formatClockDuration(0)).toBe('00:00:00');
  });

  it('labels today and yesterday explicitly', () => {
    const now = new Date(2026, 7, 15, 18, 0, 0).getTime();
    const today = new Date(2026, 7, 15, 10, 42, 0).getTime();
    const yesterday = new Date(2026, 7, 14, 18, 18, 0).getTime();
    expect(formatDayTime(today, now)).toMatch(/^Today,/);
    expect(formatDayTime(yesterday, now)).toMatch(/^Yesterday,/);
  });

  it('reports older times in coarse units', () => {
    const now = 1_700_000_000_000;
    expect(formatRelative(now - 3 * 86400 * 1000, now)).toMatch(/day/);
    expect(formatRelative(now - 5 * 3600 * 1000, now)).toMatch(/hour/);
  });

  it('handles clock skew without producing nonsense', () => {
    const now = 1_700_000_000_000;
    expect(formatRelative(now + 60_000, now)).toBe('In the future');
  });
});

describe('humanise', () => {
  it('turns capability names into labels', () => {
    expect(humanise('remote_desktop_view')).toBe('Remote desktop view');
    expect(humanise('file_write')).toBe('File write');
  });

  it('turns dotted action names into labels', () => {
    expect(humanise('pairing.completed')).toBe('Pairing · completed');
  });

  it('handles an empty string without throwing', () => {
    expect(humanise('')).toBe('');
  });
});
