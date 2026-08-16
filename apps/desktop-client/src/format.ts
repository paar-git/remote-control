/**
 * Presentation helpers.
 *
 * Kept separate from components so the formatting rules — especially fingerprint
 * grouping, which the operator relies on to compare two screens — are unit-testable.
 */

/**
 * A nine-digit display identity, grouped like a phone number.
 *
 * Derived from a fingerprint or device-id string so the same machine always shows the
 * same number. It is for reading out and recognising a machine, not for routing — there
 * is no directory behind it.
 */
export function formatDeviceId(source: string): string {
  const hex = source.replace(/[^0-9a-fA-F]/g, '');
  if (hex.length < 8) return '—';
  const n = Number(BigInt(`0x${hex.slice(0, 12)}`) % 1_000_000_000n);
  const digits = n.toString().padStart(9, '0');
  return `${digits.slice(0, 3)} ${digits.slice(3, 6)} ${digits.slice(6, 9)}`;
}

/** Strip grouping spaces from a displayed device id. */
export function compactDeviceId(formatted: string): string {
  return formatted.replace(/\s+/g, '');
}

/** Format a fingerprint as uppercase groups of four, matching the Rust display form. */
export function formatFingerprintGroups(hex: string): string {
  return (hex.toUpperCase().match(/.{1,4}/g) ?? []).join(' ');
}

/** First and last groups of a fingerprint, for compact display. */
export function abbreviateFingerprint(hex: string): string {
  const groups = formatFingerprintGroups(hex).split(' ');
  if (groups.length <= 4) return groups.join(' ');
  return `${groups.slice(0, 2).join(' ')} … ${groups.slice(-2).join(' ')}`;
}

/** Format an absolute timestamp for display, or a dash when absent. */
export function formatTimestamp(ms: number | null): string {
  if (ms === null) return '—';
  return new Date(ms).toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

/** Format a timestamp as a coarse relative age, e.g. "3 days ago". */
export function formatRelative(ms: number | null, nowMs: number = Date.now()): string {
  if (ms === null) return 'Never';

  const seconds = Math.round((nowMs - ms) / 1000);
  if (seconds < 0) return 'In the future';
  if (seconds < 60) return 'Just now';

  const units: readonly (readonly [number, Intl.RelativeTimeFormatUnit])[] = [
    [60, 'minute'],
    [3600, 'hour'],
    [86400, 'day'],
    [2592000, 'month'],
    [31536000, 'year'],
  ];

  let chosen: readonly [number, Intl.RelativeTimeFormatUnit] = [60, 'minute'];
  for (const unit of units) {
    if (seconds >= unit[0]) chosen = unit;
  }

  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
  return formatter.format(-Math.floor(seconds / chosen[0]), chosen[1]);
}

/** Turn a snake_case capability or action name into a readable label. */
export function humanise(name: string): string {
  const spaced = name.replaceAll('_', ' ').replaceAll('.', ' · ');
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

/**
 * Format a byte count for display.
 *
 * Binary units, because that is what an operating system reports: a "1 TB" disk shows
 * as 931 GiB in every tool the operator already uses, and quietly switching to decimal
 * units here would make this screen disagree with all of them.
 */
export function formatBytes(bytes: number): string {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
  if (bytes < 1024) return `${String(Math.round(bytes))} B`;

  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  // One decimal below 100, none above: "1.4 GiB" is useful, "847.3 GiB" is noise.
  return `${value < 100 ? value.toFixed(1) : String(Math.round(value))} ${units[unit] ?? 'B'}`;
}

/** Format a transfer rate, or a dash when nothing is flowing. */
export function formatRate(bytesPerSecond: number): string {
  if (bytesPerSecond === 0) return '—';
  return `${formatBytes(bytesPerSecond)}/s`;
}

/**
 * Format a duration in seconds as an uptime.
 *
 * Coarse on purpose: nobody reads "17 days, 4 hours, 32 minutes and 9 seconds" off a
 * dashboard, and the seconds change while they are reading it.
 */
/** Clock-style duration, e.g. `00:06:21`. */
export function formatClockDuration(seconds: number): string {
  const total = Math.max(0, Math.floor(seconds));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const remainder = total % 60;
  return `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(remainder).padStart(2, '0')}`;
}

/** Absolute time with a Today/Yesterday prefix when it applies. */
export function formatDayTime(ms: number, nowMs: number = Date.now()): string {
  const date = new Date(ms);
  const now = new Date(nowMs);
  const time = date.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
  const startOf = (value: Date): number =>
    new Date(value.getFullYear(), value.getMonth(), value.getDate()).getTime();
  const diffDays = Math.round((startOf(now) - startOf(date)) / 86_400_000);
  if (diffDays === 0) return `Today, ${time}`;
  if (diffDays === 1) return `Yesterday, ${time}`;
  return date.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  });
}

export function formatDuration(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);

  if (days > 0) return `${String(days)}d ${String(hours)}h`;
  if (hours > 0) return `${String(hours)}h ${String(minutes)}m`;
  if (minutes > 0) return `${String(minutes)}m`;
  return `${String(Math.floor(seconds))}s`;
}
