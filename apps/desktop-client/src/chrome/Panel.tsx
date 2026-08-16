/**
 * Flat desktop panel — a bordered rectangle, not a floating card.
 */

export function Panel({
  children,
  className = '',
  testId,
}: {
  readonly children?: React.ReactNode | undefined;
  readonly className?: string | undefined;
  readonly testId?: string | undefined;
}): React.JSX.Element {
  return (
    <section
      data-testid={testId}
      className={`flex h-full min-h-0 flex-col overflow-hidden rounded-[4px] border border-(--color-border) bg-(--color-card) ${className}`}
    >
      {children}
    </section>
  );
}

export function PanelHeader({
  title,
  trailing,
}: {
  readonly title: string;
  readonly trailing?: React.ReactNode | undefined;
}): React.JSX.Element {
  return (
    <div className="flex h-14 shrink-0 items-center justify-between gap-3 px-[22px]">
      <h2 className="text-[17px] font-medium">{title}</h2>
      {trailing}
    </div>
  );
}

export function PanelSeeAll({
  label,
  onClick,
}: {
  readonly label: string;
  readonly onClick: () => void;
}): React.JSX.Element {
  return (
    <button
      type="button"
      onClick={onClick}
      className="text-[13px] text-(--color-text-muted) underline decoration-(--color-text-muted)/50 underline-offset-2 hover:text-(--color-text-secondary)"
    >
      {label}
    </button>
  );
}
