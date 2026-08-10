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
      <label htmlFor={id} className="text-xs font-medium text-(--color-text-secondary)">
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
            'h-9 w-full min-w-0 rounded-lg border bg-(--color-surface) px-3 text-sm ' +
            'transition-[border-color,background-color] duration-150 ease-(--ease-ui) ' +
            'placeholder:text-(--color-text-muted) hover:border-(--color-border-strong) ' +
            (invalid ? 'border-(--color-danger) ' : 'border-(--color-border-strong) ') +
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

/** A `<select>` with the same footprint and treatment as {@link TextField}. */
export function SelectField({
  label,
  value,
  onChange,
  options,
  className = '',
}: {
  readonly label: string;
  readonly value: string;
  readonly onChange: (value: string) => void;
  readonly options: readonly { readonly id: string; readonly label: string }[];
  readonly className?: string | undefined;
}): React.JSX.Element {
  const id = useId();

  return (
    <div className={`flex flex-col gap-1.5 ${className}`}>
      <label htmlFor={id} className="text-xs font-medium text-(--color-text-secondary)">
        {label}
      </label>
      <select
        id={id}
        value={value}
        onChange={(event) => {
          onChange(event.target.value);
        }}
        className="h-9 rounded-lg border border-(--color-border-strong) bg-(--color-surface) px-2.5 text-sm transition-colors duration-150 ease-(--ease-ui) hover:border-(--color-text-muted)"
      >
        {options.map((option) => (
          <option key={option.id} value={option.id}>
            {option.label}
          </option>
        ))}
      </select>
    </div>
  );
}
