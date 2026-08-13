/**
 * The shared component library.
 *
 * Screens import from here rather than from the individual modules, so the set of
 * primitives the app is built from is visible in one place and a screen that reaches for
 * something outside it is obvious in review.
 *
 * Everything exported here has a caller outside the kit. A primitive nobody uses is not
 * a library, it is a maintenance cost that looks like one — so when a screen goes,
 * whatever it was the only user of goes with it.
 *
 * `Tooltip` and `StatusDot` are deliberately absent: both are still used, but only from
 * inside this directory (by `Button` and `StatusBadge`). Exporting a component with no
 * caller outside the kit invites one.
 */

export { Button, IconButton, type ButtonSize, type ButtonVariant } from './Button';
export { Card, CardHeader } from './Card';
export { CopyButton } from './CopyButton';
export { TextField } from './Field';
export {
  ConfirmDialog,
  EmptyState,
  ErrorState,
  Skeleton,
  SkeletonRows,
  ToastBar,
  type Toast,
} from './Feedback';
export { PageHeader } from './PageHeader';
export { Badge, StatusBadge, type StatusTone } from './Status';
