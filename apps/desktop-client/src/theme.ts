/**
 * Colour theme. Dark is the product default; light and system remain available.
 *
 * Stored locally so the choice survives a restart. The document `data-theme` attribute
 * is the only thing CSS reads; this module is the only writer.
 */

export type ThemePreference = 'light' | 'dark' | 'system';

const STORAGE_KEY = 'rc-theme';

export function loadTheme(): ThemePreference {
  const stored = window.localStorage.getItem(STORAGE_KEY);
  if (stored === 'light' || stored === 'dark' || stored === 'system') return stored;
  return 'dark';
}

export function resolvedTheme(preference: ThemePreference): 'light' | 'dark' {
  if (preference !== 'system') return preference;
  if (typeof window.matchMedia !== 'function') return 'light';
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

export function applyTheme(preference: ThemePreference): void {
  document.documentElement.dataset['theme'] = resolvedTheme(preference);
}

export function saveTheme(preference: ThemePreference): void {
  window.localStorage.setItem(STORAGE_KEY, preference);
  applyTheme(preference);
}
