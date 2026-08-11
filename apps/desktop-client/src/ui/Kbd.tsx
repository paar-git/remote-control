/**
 * A keyboard keycap.
 *
 * Only ever rendered for a shortcut that is actually bound. A decorative keycap teaches
 * the operator a key that does nothing, which is worse than showing no shortcut at all.
 */
export function Kbd({ children }: { readonly children: React.ReactNode }): React.JSX.Element {
  return (
    <kbd className="rounded border border-(--color-border) bg-(--color-card) px-1.5 py-px font-sans text-[10px] leading-4 font-medium text-(--color-text-secondary)">
      {children}
    </kbd>
  );
}
