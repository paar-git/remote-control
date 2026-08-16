/**
 * Choosing which remote monitor to look at.
 *
 * # The map is the control
 *
 * A list of names tells you a machine has three monitors. It does not tell you which
 * one is on the left, and that is the only thing the operator actually needs in order
 * to pick the right one. So the picker draws the real arrangement — proportional sizes,
 * real relative positions, negative offsets and all — and each rectangle *is* the
 * button.
 *
 * The layout comes from the host's reported geometry, so a monitor above and to the
 * left renders above and to the left. Nothing here assumes a row.
 *
 * # Names are untrusted
 *
 * A display's name comes from the remote OS and is rendered as text, never as markup.
 */

import { Monitor } from 'lucide-react';

import { describeDisplay, layoutDisplays, type RemoteDisplay } from './displays';

export function DisplaySelector({
  displays,
  active,
  onSelect,
}: {
  readonly displays: readonly RemoteDisplay[];
  /** The display currently being viewed. */
  readonly active: number;
  readonly onSelect: (index: number) => void;
}): React.JSX.Element | null {
  // One monitor needs no picker, and an empty list has nothing to pick. Rendering
  // either would be chrome that never does anything.
  if (displays.length < 2) return null;

  const boxes = layoutDisplays(displays);

  return (
    <div className="flex flex-col gap-2">
      <div
        role="group"
        aria-label="Remote displays"
        className={
          'relative h-24 w-full rounded-lg border border-(--color-border) ' +
          'bg-(--color-surface) p-1'
        }
      >
        {boxes.map(({ display, left, top, width, height }) => {
          const selected = display.index === active;
          return (
            <button
              key={display.index}
              type="button"
              aria-pressed={selected}
              aria-label={`${display.name}${display.primary ? ', main display' : ''}, ${describeDisplay(display)}`}
              title={`${display.name} — ${describeDisplay(display)}`}
              onClick={() => {
                onSelect(display.index);
              }}
              style={{
                position: 'absolute',
                left: `${left}%`,
                top: `${top}%`,
                width: `${width}%`,
                height: `${height}%`,
              }}
              className={
                'flex flex-col items-center justify-center overflow-hidden rounded-md ' +
                'border p-0.5 text-[10px] leading-tight transition-colors duration-150 ' +
                'ease-(--ease-ui) focus-visible:outline-2 focus-visible:outline-offset-1 ' +
                'focus-visible:outline-(--color-accent) ' +
                (selected
                  ? 'border-(--color-accent) bg-(--color-accent)/15 text-(--color-text)'
                  : 'border-(--color-border) bg-(--color-card) ' +
                    'text-(--color-text-secondary) hover:bg-(--color-hover)')
              }
            >
              <span className="font-medium">{display.index + 1}</span>
              {display.primary && <span className="opacity-70">Main</span>}
            </button>
          );
        })}
      </div>

      <ul className="flex flex-col gap-1">
        {displays.map((display) => {
          const selected = display.index === active;
          return (
            <li key={display.index}>
              <button
                type="button"
                aria-pressed={selected}
                onClick={() => {
                  onSelect(display.index);
                }}
                className={
                  'flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-left text-xs ' +
                  'transition-colors duration-150 ease-(--ease-ui) ' +
                  'focus-visible:outline-2 focus-visible:outline-offset-2 ' +
                  'focus-visible:outline-(--color-accent) ' +
                  (selected ? 'bg-(--color-hover)' : 'hover:bg-(--color-hover)')
                }
              >
                <Monitor
                  aria-hidden="true"
                  className={
                    'size-3.5 shrink-0 ' +
                    (selected ? 'text-(--color-accent)' : 'text-(--color-text-secondary)')
                  }
                />
                <span className="min-w-0 flex-1 truncate">
                  Display {display.index + 1}
                  {display.primary && (
                    <span className="text-(--color-text-secondary)"> · Main</span>
                  )}
                </span>
                <span className="shrink-0 text-(--color-text-secondary)">
                  {describeDisplay(display)}
                </span>
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
