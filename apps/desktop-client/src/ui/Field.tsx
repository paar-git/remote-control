/**
 * Form fields.
 *
 * A label, a control and its help text are one component so they cannot be wired up
 * inconsistently: the label always points at the control, and the help text is always
 * referenced by `aria-describedby` rather than merely sitting next to it.
 */

import { useId } from 'react';

export function TextField({
  label,
  value,
  onChange,
  type = 'text',
  placeholder,
  help,
  error,
  mono = false,
  autoComplete,
  maxLength,
  required = false,
  autoFocus = false,
  uppercase = false,
  className = '',
  trailing,
}: {
  readonly label: string;
  readonly value: string;
  readonly onChange: (value: string) => void;
  readonly type?: 'text' | 'password' | undefined;
  readonly placeholder?: string | undefined;
  readonly help?: React.ReactNode | undefined;
  /** Marks the control invalid and replaces the help text. */
  readonly error?: string | null | undefined;
  readonly mono?: boolean | undefined;
  readonly autoComplete?: string | undefined;
  readonly maxLength?: number | undefined;
  readonly required?: boolean | undefined;
  readonly autoFocus?: boolean | undefined;
  readonly uppercase?: boolean | undefined;
  readonly className?: string | undefined;
  /** Rendered after the input, inside the field's column. */
  readonly trailing?: React.ReactNode | undefined;
}): React.JSX.Element {
  const id = useId();
  const helpId = `${id}-help`;
  const invalid = error !== undefined && error !== null && error !== '';

  return (
    <div className={`flex flex-col gap-1.5 ${className}`}>
      <label htmlFor={id} className="text-sm font-medium text-(--color-text-secondary)">
        {label}
      </label>
      <div className="flex items-center gap-2">
        <input
          id={id}
          type={type}
          value={value}
          onChange={(event) => {
            onChange(event.target.value);
          }}
          placeholder={placeholder}
          autoComplete={autoComplete}
          maxLength={maxLength}
          required={required}
          autoFocus={autoFocus}
          spellCheck={mono ? false : undefined}
          aria-invalid={invalid || undefined}
          aria-describedby={help !== undefined || invalid ? helpId : undefined}
          className={
            'h-11 w-full min-w-0 rounded-xl border bg-(--color-page) px-3.5 text-[15px] ' +
            'transition-[border-color,background-color] duration-150 ease-(--ease-ui) ' +
            'placeholder:text-(--color-text-secondary) hover:border-(--color-border-hover) ' +
            (invalid ? 'border-(--color-danger) ' : 'border-(--color-border) ') +
            (mono ? 'font-mono ' : '') +
            (uppercase ? 'tracking-[0.12em] uppercase ' : '')
          }
        />
        {trailing}
      </div>
      {(invalid || help !== undefined) && (
        <p
          id={helpId}
          className={`text-xs ${invalid ? 'text-(--color-danger)' : 'text-(--color-text-secondary)'}`}
        >
          {invalid ? error : help}
        </p>
      )}
    </div>
  );
}
