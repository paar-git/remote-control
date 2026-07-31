/**
 * Presentation helpers.
 *
 * Kept separate from components so the formatting rules — especially fingerprint
 * grouping, which the operator relies on to compare two screens — are unit-testable.
 */

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
