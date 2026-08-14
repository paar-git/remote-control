/**
 * Persistent chrome: a labelled sidebar and a view that remounts on each category.
 *
 * Every item leads somewhere. A disabled navigation item is a placeholder, which is the
 * thing this shell exists to remove.
 */

import { MonitorCog } from 'lucide-react';

import { VIEWS, type View } from './navigation.js';

export function AppShell({
  view,
  onNavigate,
  banner,
  children,
}: {
  readonly view: View;
  readonly onNavigate: (view: View) => void;
  readonly banner: React.ReactNode;
  readonly children: React.ReactNode;
}): React.JSX.Element {
  return (
    <div className="flex h-full min-h-0">
      <aside className="flex w-[216px] shrink-0 flex-col border-r border-(--color-border) bg-(--color-sidebar) px-3 py-4">
        <div className="mb-5 flex items-center gap-2.5 px-2">
          <span className="flex size-8 items-center justify-center rounded-xl bg-(--color-accent) text-(--color-accent-text)">
            <MonitorCog aria-hidden="true" className="size-4" />
          </span>
          <p className="text-sm font-semibold tracking-tight">RC</p>
        </div>

        <nav aria-label="Main" className="flex flex-col gap-0.5">
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
                  'flex h-10 items-center gap-2.5 rounded-xl px-3 text-sm font-medium ' +
                  'transition-colors duration-150 ease-(--ease-ui) ' +
                  (current
                    ? 'bg-(--color-accent-soft) text-(--color-accent)'
                    : 'text-(--color-text-secondary) hover:bg-(--color-hover) hover:text-(--color-text)')
                }
              >
                <Icon aria-hidden="true" className="size-4 shrink-0" />
                {item.label}
              </button>
            );
          })}
        </nav>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        {banner}
        <main key={view} className="animate-view-in min-h-0 flex-1 overflow-y-auto p-6">
          {children}
        </main>
      </div>
    </div>
  );
}
