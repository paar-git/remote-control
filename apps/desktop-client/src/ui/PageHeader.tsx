/**
 * The heading block every screen opens with.
 *
 * Uniform so that the answer to "where am I, what is this, what can I do here" is always
 * in the same place. `actions` sits on the same line as the title on a wide window and
 * wraps beneath it on a narrow one.
 */
export function PageHeader({
  title,
  description,
  actions,
  meta,
}: {
  readonly title: string;
  readonly description?: React.ReactNode | undefined;
  /** Primary and secondary actions for the screen. */
  readonly actions?: React.ReactNode | undefined;
  /** Status shown directly beneath the title, e.g. a device name and a state. */
  readonly meta?: React.ReactNode | undefined;
}): React.JSX.Element {
  return (
    <header className="mb-3 flex flex-wrap items-start justify-between gap-x-6 gap-y-2">
      <div className="min-w-0">
        <h2 className="text-[17px] font-medium">{title}</h2>
        {meta !== undefined && (
          <div className="mt-1.5 flex flex-wrap items-center gap-2">{meta}</div>
        )}
        {description !== undefined && (
          <p className="mt-1.5 max-w-2xl text-sm text-(--color-text-secondary)">{description}</p>
        )}
      </div>
      {actions !== undefined && <div className="flex shrink-0 flex-wrap gap-2">{actions}</div>}
    </header>
  );
}
