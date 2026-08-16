/**
 * A compact device mark: OS icon when we know the family, otherwise the name's initial.
 */

import { Apple, Laptop, Monitor } from 'lucide-react';

export function DeviceAvatar({
  name,
  os,
}: {
  readonly name: string;
  readonly os?: 'windows' | 'linux' | 'macos' | 'unknown' | undefined;
}): React.JSX.Element {
  const initial = (name.trim().charAt(0) || '?').toUpperCase();

  return (
    <span
      aria-hidden="true"
      className="flex size-10 shrink-0 items-center justify-center rounded-xl bg-(--color-accent-soft) text-(--color-accent)"
    >
      {os === 'macos' ? (
        <Apple className="size-5" />
      ) : os === 'linux' ? (
        <Laptop className="size-5" />
      ) : os === 'windows' ? (
        <Monitor className="size-5" />
      ) : (
        <span className="text-sm font-semibold">{initial}</span>
      )}
    </span>
  );
}
