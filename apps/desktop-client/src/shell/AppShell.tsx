/**
 * The application frame: sidebar, toolbar, and the scrolling content column.
 *
 * The content column is capped rather than left to fill an arbitrarily wide window —
 * a line of text 2,000 pixels long is unreadable — but the cap is generous enough for a
 * three-column grid, so the page uses the space it is given instead of huddling in a
 * narrow panel.
 */

export function AppShell({
  sidebar,
  toolbar,
  banner,
  children,
}: {
  readonly sidebar: React.ReactNode;
  readonly toolbar: React.ReactNode;
  /** An app-wide notice shown above the content, e.g. a waiting update. */
  readonly banner?: React.ReactNode | undefined;
  readonly children: React.ReactNode;
}): React.JSX.Element {
  return (
    <div className="flex h-full overflow-hidden bg-(--color-page)">
      {sidebar}
      <main className="flex min-w-0 flex-1 flex-col">
        {toolbar}
        {banner}
        <div className="flex flex-1 flex-col overflow-y-auto">
          <div className="mx-auto flex w-full max-w-[1280px] flex-1 flex-col px-6 py-6">
            {children}
          </div>
        </div>
      </main>
    </div>
  );
}
