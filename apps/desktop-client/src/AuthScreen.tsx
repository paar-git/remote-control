/**
 * The gate: owner-account creation on first run, and unlock thereafter.
 *
 * This is the first thing anyone sees, so it says what the application is before it asks
 * for anything. The setup copy is explicit that there is no recovery, because the
 * consequence of forgetting this password is total and cannot be undone later.
 */

import { KeyRound, MonitorCog, ShieldCheck } from 'lucide-react';
import { useState } from 'react';

import { type OwnerStatus, createOwner, ownerLogin } from './api.js';
import { Button, TextField, type Toast } from './ui';

export function AuthScreen({
  mode,
  onAuthenticated,
  onToast,
}: {
  readonly mode: 'setup' | 'locked';
  readonly onAuthenticated: (status: OwnerStatus) => void;
  readonly onToast: (toast: Toast) => void;
}): React.JSX.Element {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const setupMode = mode === 'setup';

  const submit = (event: React.FormEvent): void => {
    event.preventDefault();
    setError(null);

    if (setupMode && password !== confirm) {
      setError('The two passwords do not match.');
      return;
    }

    setBusy(true);
    const action = setupMode
      ? createOwner(username, password).then(() => ownerLogin(username, password))
      : ownerLogin(username, password);

    action
      .then((status) => {
        setPassword('');
        setConfirm('');
        if (setupMode) onToast({ kind: 'success', message: 'Owner account created.' });
        onAuthenticated(status);
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : 'Could not sign in.');
        setPassword('');
      })
      .finally(() => {
        setBusy(false);
      });
  };

  return (
    <div className="flex h-full items-center justify-center overflow-y-auto bg-(--color-surface) p-6">
      <div className="animate-fade-in w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center text-center">
          <span className="mb-3 flex size-12 items-center justify-center rounded-2xl bg-(--color-accent) text-(--color-accent-text) shadow-lg shadow-black/30">
            <MonitorCog aria-hidden="true" className="size-6" />
          </span>
          <h1 className="text-lg font-semibold tracking-[-0.01em]">
            {setupMode ? 'Set up Remote Control' : 'Remote Control'}
          </h1>
          <p className="mt-1 text-sm text-(--color-text-secondary)">
            {setupMode
              ? 'Create the owner account for this computer.'
              : 'Locked. Enter your owner password to continue.'}
          </p>
        </div>

        <form
          onSubmit={submit}
          className="rounded-xl border border-(--color-border-subtle) bg-(--color-surface-raised) p-5 shadow-xl shadow-black/20"
        >
          <div className="flex flex-col gap-4">
            <TextField
              label="Username"
              value={username}
              onChange={setUsername}
              autoComplete="username"
              maxLength={64}
              required
              autoFocus
            />

            <TextField
              label="Password"
              type="password"
              value={password}
              onChange={setPassword}
              autoComplete={setupMode ? 'new-password' : 'current-password'}
              required
              help={
                setupMode
                  ? 'At least 12 characters. Stored as an Argon2id hash, never in plain text.'
                  : undefined
              }
            />

            {setupMode && (
              <TextField
                label="Confirm password"
                type="password"
                value={confirm}
                onChange={setConfirm}
                autoComplete="new-password"
                required
              />
            )}
          </div>

          {error !== null && (
            <p role="alert" className="mt-4 text-sm text-(--color-danger)">
              {error}
            </p>
          )}

          <Button
            type="submit"
            variant="primary"
            disabled={busy}
            icon={setupMode ? ShieldCheck : KeyRound}
            className="mt-5 h-9 w-full"
          >
            {busy ? 'Working…' : setupMode ? 'Create account' : 'Unlock'}
          </Button>
        </form>

        {setupMode && (
          <p className="mt-4 text-center text-xs text-(--color-text-muted)">
            There is no default password and no recovery. Choose something you will not lose.
          </p>
        )}
      </div>
    </div>
  );
}
