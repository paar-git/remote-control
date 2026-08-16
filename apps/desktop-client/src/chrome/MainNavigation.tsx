/**
 * Horizontal product navigation. Selected item is red text plus a hairline underline.
 */

import { VIEWS, type View } from '../navigation.js';

export function MainNavigation({
  view,
  onNavigate,
}: {
  readonly view: View;
  readonly onNavigate: (view: View) => void;
}): React.JSX.Element {
  return (
    <nav aria-label="Main" className="shrink-0 border-b border-(--color-border)">
      <div className="rc-content flex h-[44px] items-stretch gap-7">
        {VIEWS.map((item) => {
          const current = item.id === view;
          const Icon = item.icon;
          return (
            <button
              key={item.id}
              type="button"
              aria-current={current ? 'page' : undefined}
              onClick={() => {
                onNavigate(item.id);
              }}
              className={
                'relative flex items-center gap-2 pr-2 text-[15px] transition-colors duration-125 ' +
                (current
                  ? 'font-medium text-(--color-accent)'
                  : 'text-(--color-text-secondary) hover:text-(--color-text)')
              }
            >
              <Icon aria-hidden="true" className="size-[18px] shrink-0" />
              {item.label}
              {current && (
                <span
                  aria-hidden="true"
                  className="absolute inset-x-0 -bottom-px h-0.5 bg-(--color-accent)"
                />
              )}
            </button>
          );
        })}
      </div>
    </nav>
  );
}
