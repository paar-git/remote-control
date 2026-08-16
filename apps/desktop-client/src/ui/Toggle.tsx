/**
 * An on/off switch that reports the machine's state, not the user's last click.
 */

export function Toggle({
  checked,
  onChange,
  label,
  disabled = false,
}: {
  readonly checked: boolean;
  readonly onChange: (next: boolean) => void;
  readonly label: string;
  readonly disabled?: boolean | undefined;
}): React.JSX.Element {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => {
        onChange(!checked);
      }}
      className={
        'relative inline-flex h-[28px] w-[50px] shrink-0 items-center rounded-full transition-colors ' +
        'duration-125 ease-(--ease-ui) disabled:opacity-45 ' +
        (checked ? 'bg-(--color-accent)' : 'bg-(--color-border-hover)')
      }
    >
      <span
        className={
          'inline-block size-[22px] rounded-full bg-white transition-transform ' +
          'duration-125 ease-(--ease-ui) ' +
          (checked ? 'translate-x-[25px]' : 'translate-x-[3px]')
        }
      />
    </button>
  );
}
