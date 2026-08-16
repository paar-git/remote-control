/**
 * A compact device mark: OS icon when we know the family, otherwise the name's initial.
 */

import { Apple, Laptop, Monitor } from 'lucide-react';

export function DeviceAvatar({
  name,
  os,
  size = 'md',
}: {
  readonly name: string;
  readonly os?: 'windows' | 'linux' | 'macos' | 'unknown' | undefined;
  readonly size?: 'sm' | 'md' | 'lg' | undefined;
}): React.JSX.Element {
  const initial = (name.trim().charAt(0) || '?').toUpperCase();
  const box = size === 'sm' ? 'size-[30px]' : size === 'lg' ? 'size-[50px]' : 'size-10';
  const glyph = size === 'lg' ? 'size-6' : size === 'sm' ? 'size-[18px]' : 'size-5';

  return (
    <span
      aria-hidden="true"
      className={`flex ${box} shrink-0 items-center justify-center rounded-[4px] border border-(--color-accent) bg-(--color-page) text-(--color-accent)`}
    >
      {os === 'macos' ? (
        <Apple className={glyph} />
      ) : os === 'linux' ? (
        <Laptop className={glyph} />
      ) : os === 'windows' ? (
        <Monitor className={glyph} />
      ) : (
        <span className="text-sm font-semibold">{initial}</span>
      )}
    </span>
  );
}
