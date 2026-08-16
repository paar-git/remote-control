/**
 * Canonical RC mark geometry.
 *
 * Two angular screens plus a connection chevron. Filled shapes only — no
 * 1px strokes — so the mark stays clear at 100%, 125% and 150% UI scale.
 * ViewBox is 21×21; the composition is optically lifted ~0.4 units so it
 * sits with 15px Semibold “RC” rather than looking a pixel low.
 */

export const RC_MARK_VIEWBOX = '0 0 21 21';
export const RC_MARK_COLOR = '#FF413D';

/** Screen frames (even-odd cutouts) and the linking chevron. */
export const RC_MARK_SCREENS =
  'M1.7 1.4h10.6v8.1H1.7zm1.9 2.55h6.8v4.15H3.6zM8.7 11.1h10.6v8.1H8.7zm1.9 2.55h6.8v4.15h-6.8z';

export const RC_MARK_LINK = 'M7.15 8.85h2.7l1.95 1.7-1.95 1.7H7.15l1.75-1.7z';

export function rcMarkSvg(size: number, color: string = RC_MARK_COLOR): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${String(size)}" height="${String(size)}" viewBox="${RC_MARK_VIEWBOX}" fill="none"><path fill="${color}" fill-rule="evenodd" d="${RC_MARK_SCREENS}"/><path fill="${color}" d="${RC_MARK_LINK}"/></svg>`;
}
