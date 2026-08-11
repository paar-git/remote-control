/**
 * The live connection state, shared by everything that displays it.
 *
 * The backend owns the connection, so the UI reads it rather than keeping a copy: a
 * state the UI invented could disagree with the session that is actually open. One hook
 * means the sidebar, the top bar, Home and Devices all show the same answer at the same
 * time instead of polling independently and disagreeing for a second.
 */

import { useCallback, useEffect, useState } from 'react';

import { type ConnectionState, getConnectionState, isBusy, isConnected } from './api.js';
import type { StatusTone } from './ui';

const POLL_MS = 1000;

export interface Connection {
  readonly state: ConnectionState;
  /** Replaces the polled value immediately after an action returns a new one. */
  readonly set: (next: ConnectionState) => void;
}

export function useConnectionState(enabled: boolean): Connection {
  const [state, setState] = useState<ConnectionState>({ state: 'offline' });

  useEffect(() => {
    if (!enabled) return;

    let cancelled = false;
    const read = (): void => {
      getConnectionState()
        .then((next) => {
          if (!cancelled) setState(next);
        })
        .catch(() => {
          // A failed poll says nothing about the connection; leaving the last known
          // state is better than flickering to "offline".
        });
    };

    read();
    const timer = window.setInterval(read, POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [enabled]);

  const set = useCallback((next: ConnectionState) => {
    setState(next);
  }, []);

  return { state, set };
}

/** The status tone for a connection state. */
export function connectionTone(state: ConnectionState): StatusTone {
  if (state.state === 'refused' || state.state === 'failed') return 'danger';
  if (isConnected(state)) return 'ready';
  if (isBusy(state)) return 'busy';
  return 'idle';
}

/**
 * A two-or-three word label for a connection state.
 *
 * Deliberately shorter than `describeConnectionState`, which is a full sentence: this is
 * for a badge in a status bar, where the sentence belongs in the tooltip instead.
 */
export function connectionLabel(state: ConnectionState): string {
  switch (state.state) {
    case 'offline':
      return 'Not connected';
    case 'connecting':
      return 'Connecting';
    case 'authenticating':
      return 'Verifying';
    case 'connected':
      return 'Connected';
    case 'disconnecting':
      return 'Disconnecting';
    case 'reconnecting':
      return 'Reconnecting';
    case 'waiting_to_retry':
      return 'Retrying';
    case 'refused':
      return 'Refused';
    case 'failed':
      return 'Failed';
  }
}
