/**
 * Desktop split button: primary action plus a narrow chevron menu.
 */

import { ChevronDown } from 'lucide-react';
import { useEffect, useId, useRef, useState } from 'react';

export function SplitButton({
  label,
  onClick,
  disabled = false,
  variant = 'primary',
  size = 'lg',
  busy = false,
  menu,
}: {
  readonly label: string;
  readonly onClick: () => void;
  readonly disabled?: boolean | undefined;
  readonly variant?: 'primary' | 'neutral' | undefined;
  readonly size?: 'lg' | 'md' | undefined;
  readonly busy?: boolean | undefined;
  readonly menu?: React.ReactNode | undefined;
}): React.JSX.Element {
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const menuId = useId();

  useEffect(() => {
    if (!open) return;
    const onPointer = (event: PointerEvent): void => {
      if (root.current !== null && !root.current.contains(event.target as Node)) {
        setOpen(false);
      }
    };
    const onKey = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') setOpen(false);
    };
    window.addEventListener('pointerdown', onPointer);
    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('pointerdown', onPointer);
      window.removeEventListener('keydown', onKey);
    };
  }, [open]);

  const tall = size === 'lg';
  const primary =
    variant === 'primary'
      ? 'bg-(--color-accent) text-(--color-accent-text) transition-colors duration-125 hover:bg-(--color-accent-hover) active:bg-(--color-accent-pressed)'
      : 'bg-(--color-hover) text-(--color-text) transition-colors duration-125 hover:bg-(--color-border)';
  const divider = variant === 'primary' ? 'bg-(--color-accent-pressed)' : 'bg-(--color-border)';

  return (
    <div ref={root} className="relative inline-flex">
      <div
        className={
          `inline-flex overflow-hidden rounded-[4px] ${primary} ` +
          (disabled ? 'pointer-events-none opacity-45 ' : '') +
          (tall ? 'h-12' : 'h-10')
        }
      >
        <button
          type="button"
          disabled={disabled}
          onClick={onClick}
          className={
            'inline-flex items-center justify-center gap-2 px-5 text-[15px] font-semibold ' +
            (tall ? 'min-w-[162px]' : 'min-w-[82px] px-3 text-[13px] font-medium')
          }
        >
          {busy ? 'Connecting…' : label}
        </button>
        <span aria-hidden="true" className={`w-px self-stretch ${divider}`} />
        <button
          type="button"
          disabled={disabled || menu === undefined}
          aria-haspopup="menu"
          aria-expanded={open}
          aria-controls={open ? menuId : undefined}
          aria-label={`${label} options`}
          onClick={() => {
            setOpen((current) => !current);
          }}
          className={
            tall ? 'flex w-12 items-center justify-center' : 'flex w-10 items-center justify-center'
          }
        >
          <ChevronDown className="size-4" />
        </button>
      </div>
      {open && menu !== undefined && (
        <div
          id={menuId}
          role="menu"
          className="absolute top-[calc(100%+4px)] right-0 z-30 min-w-full rounded-[4px] border border-(--color-border) bg-(--color-card) py-1"
        >
          <div
            onClick={() => {
              setOpen(false);
            }}
          >
            {menu}
          </div>
        </div>
      )}
    </div>
  );
}

export function SplitMenuItem({
  children,
  onClick,
}: {
  readonly children: React.ReactNode;
  readonly onClick: () => void;
}): React.JSX.Element {
  return (
    <button
      type="button"
      role="menuitem"
      onClick={onClick}
      className="flex w-full items-center px-3 py-2 text-left text-[13px] text-(--color-text) hover:bg-(--color-hover)"
    >
      {children}
    </button>
  );
}
