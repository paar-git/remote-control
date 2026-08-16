/**
 * Compact RC mark: two angular screens linked by a connection arrow.
 * Geometry lives in `brand/rc-mark.ts` so every surface draws the same symbol.
 */

import { RC_MARK_COLOR, RC_MARK_LINK, RC_MARK_SCREENS, RC_MARK_VIEWBOX } from '../brand/rc-mark';

export function RcMark({
  size = 21,
}: {
  readonly size?: number | undefined;
}): React.JSX.Element {
  return (
    <svg
      width={size}
      height={size}
      viewBox={RC_MARK_VIEWBOX}
      fill="none"
      aria-hidden="true"
      shapeRendering="geometricPrecision"
    >
      <path fill={RC_MARK_COLOR} fillRule="evenodd" d={RC_MARK_SCREENS} />
      <path fill={RC_MARK_COLOR} d={RC_MARK_LINK} />
    </svg>
  );
}
