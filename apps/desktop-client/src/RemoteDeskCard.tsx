/**
 * The primary action on the home screen: type a target and connect.
 *
 * Connect is the accent colour, never red. Red is reserved for a failed or refused
 * attempt, which this card also renders as a dedicated state rather than a spinner
 * that never resolves.
 */

import { LoaderCircle, ShieldCheck } from 'lucide-react';
import { useState } from 'react';

import { displayAddress, parseAddress } from './address.js';
import type { ConnectionState, Recent } from './api.js';
import { Button, Card, TextField } from './ui';

export function RemoteDeskCard({
  onConnect,
  busy,
  error,
  connection,
  suggestions = [],
}: {
  readonly onConnect: (address: string) => void;
  readonly busy: boolean;
  readonly error: string | null;
  readonly connection: ConnectionState;
  readonly suggestions?: readonly Recent[] | undefined;
}): React.JSX.Element {
  const [text, setText] = useState('');
  const [refusal, setRefusal] = useState<string | null>(null);
  const shown = refusal ?? error;
  const phase = connectionPhase(connection, busy, shown);

  const submit = (): void => {
    const trimmed = text.trim();
    if (/^\d[\d\s]{7,}$/.test(trimmed) && parseAddress(trimmed.replace(/\s/g, '')).ok === false) {
      setRefusal(
        'A device ID identifies a machine. Type its hostname or IP address to connect — there is no directory to look the ID up in.',
      );
      return;
    }
    const parsed = parseAddress(text);
    if (!parsed.ok) {
      setRefusal(parsed.reason);
      return;
    }
    setRefusal(null);
    onConnect(parsed.value);
  };

  return (
    <Card className="mx-auto w-full max-w-3xl text-center">
      <h2 className="mb-1 text-2xl font-semibold tracking-tight">Connect to a device</h2>
      <p className="mb-6 text-sm text-(--color-text-secondary)">
        Enter a device ID, hostname, or IP address.
      </p>

      <form
        className="text-left"
        onSubmit={(event) => {
          event.preventDefault();
          submit();
        }}
      >
        <TextField
          label="Device ID, hostname, or IP"
          value={text}
          onChange={(value) => {
            setText(value);
            setRefusal(null);
          }}
          placeholder="192.168.1.77"
          mono
          autoComplete="off"
          error={phase.kind === 'failed' || phase.kind === 'denied' ? shown : null}
          trailing={
            <Button type="submit" variant="primary" size="lg" disabled={busy}>
              {busy ? (
                <>
                  <LoaderCircle aria-hidden="true" className="size-4 animate-spin-slow" />
                  Connect
                </>
              ) : (
                'Connect'
              )}
            </Button>
          }
        />
      </form>

      {phase.kind !== 'idle' && phase.kind !== 'failed' && phase.kind !== 'denied' && (
        <p
          role="status"
          className="animate-fade-in mt-4 flex items-center justify-center gap-2 text-sm font-medium"
        >
          <LoaderCircle aria-hidden="true" className="size-4 animate-spin-slow text-(--color-accent)" />
          {phase.label}
        </p>
      )}

      {suggestions.length > 0 && (
        <div className="mt-5 flex flex-wrap items-center justify-center gap-2">
          {suggestions.slice(0, 4).map((entry) => (
            <button
              key={entry.address}
              type="button"
              disabled={busy}
              onClick={() => {
                setText(displayAddress(entry.address));
                setRefusal(null);
                onConnect(entry.address);
              }}
              className="rounded-full border border-(--color-border) px-3 py-1 text-sm text-(--color-text-secondary) transition-colors duration-150 hover:border-(--color-border-hover) hover:bg-(--color-hover) hover:text-(--color-text) disabled:opacity-45"
            >
              {entry.machineName}
            </button>
          ))}
        </div>
      )}

      <p className="mt-6 flex items-center justify-center gap-1.5 text-xs text-(--color-text-secondary)">
        <ShieldCheck aria-hidden="true" className="size-3.5 text-(--color-success)" />
        End-to-end encrypted
      </p>
    </Card>
  );
}

function connectionPhase(
  connection: ConnectionState,
  busy: boolean,
  error: string | null,
): { readonly kind: 'idle' | 'connecting' | 'waiting' | 'authenticating' | 'connected' | 'denied' | 'failed'; readonly label: string } {
  if (connection.state === 'connected') return { kind: 'connected', label: 'Connected' };
  if (connection.state === 'authenticating') {
    return { kind: 'waiting', label: 'Waiting for approval…' };
  }
  if (connection.state === 'connecting' || connection.state === 'reconnecting') {
    return { kind: 'connecting', label: 'Connecting…' };
  }
  if (connection.state === 'refused') return { kind: 'denied', label: connection.message };
  if (connection.state === 'failed') return { kind: 'failed', label: connection.message };
  if (error !== null) {
    return {
      kind: /not accept|refused|denied|identity/i.test(error) ? 'denied' : 'failed',
      label: error,
    };
  }
  if (busy) return { kind: 'connecting', label: 'Connecting…' };
  return { kind: 'idle', label: '' };
}
