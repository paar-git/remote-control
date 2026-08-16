/**
 * Shared outbound-connect form: parse, dial, and report progress.
 */

import { useCallback, useRef, useState } from 'react';

import { parseAddress } from './address.js';
import { connectToAddress, getConnectionState, isBusy, type ConnectionState } from './api.js';
import type { Toast } from './ui';

export function useConnectForm({
  connection,
  onConnection,
  onToast,
}: {
  readonly connection: ConnectionState;
  readonly onConnection: (next: ConnectionState) => void;
  readonly onToast: (toast: Toast) => void;
}): {
  readonly address: string;
  readonly setAddress: (value: string) => void;
  readonly parseError: string | null;
  readonly busy: boolean;
  readonly failed: boolean;
  readonly inputRef: React.RefObject<HTMLInputElement | null>;
  readonly submit: () => void;
  readonly submitWithPassword: (password: string) => void;
  readonly connect: (target: string, password?: string | null) => void;
  readonly clear: () => void;
} {
  const [address, setAddress] = useState('');
  const [parseError, setParseError] = useState<string | null>(null);
  const [dialing, setDialing] = useState(false);
  const inputRef = useRef<HTMLInputElement | null>(null);

  const busy = isBusy(connection) || dialing;
  const failed = connection.state === 'refused' || connection.state === 'failed';

  const connect = useCallback(
    (target: string, password: string | null = null): void => {
      if (busy) return;
      setParseError(null);
      setDialing(true);
      connectToAddress(target, password)
        .then((next) => {
          onConnection(next);
        })
        .catch((error: unknown) => {
          onToast({
            kind: 'error',
            message: error instanceof Error ? error.message : 'Could not start the connection.',
          });
          getConnectionState()
            .then(onConnection)
            .catch(() => undefined);
        })
        .finally(() => {
          setDialing(false);
        });
    },
    [busy, onConnection, onToast],
  );

  const submit = useCallback((): void => {
    const trimmed = address.trim();
    if (/^\d{3}\s?\d{3}\s?\d{3}$/.test(trimmed) || /^\d{9}$/.test(trimmed.replace(/\s/g, ''))) {
      setParseError(
        'A device ID identifies a machine. Type its hostname or IP address to connect — there is no directory to look the ID up in.',
      );
      return;
    }
    const parsed = parseAddress(address);
    if (!parsed.ok) {
      setParseError(parsed.reason);
      return;
    }
    connect(parsed.value, null);
  }, [address, connect]);

  const submitWithPassword = useCallback(
    (password: string): void => {
      const trimmed = address.trim();
      if (/^\d{3}\s?\d{3}\s?\d{3}$/.test(trimmed) || /^\d{9}$/.test(trimmed.replace(/\s/g, ''))) {
        setParseError(
          'A device ID identifies a machine. Type its hostname or IP address to connect — there is no directory to look the ID up in.',
        );
        return;
      }
      const parsed = parseAddress(address);
      if (!parsed.ok) {
        setParseError(parsed.reason);
        return;
      }
      const secret = password.trim();
      if (secret === '') {
        setParseError('Enter the unattended password for that machine.');
        return;
      }
      connect(parsed.value, secret);
    },
    [address, connect],
  );

  const clear = useCallback((): void => {
    setAddress('');
    setParseError(null);
    window.setTimeout(() => {
      inputRef.current?.focus();
    }, 0);
  }, []);

  const updateAddress = useCallback((value: string): void => {
    setAddress(value);
    setParseError(null);
  }, []);

  return {
    address,
    setAddress: updateAddress,
    parseError,
    busy,
    failed,
    inputRef,
    submit,
    submitWithPassword,
    connect,
    clear,
  };
}
