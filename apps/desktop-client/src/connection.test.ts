/**
 * Tests for the connection-state helpers the UI branches on.
 *
 * These are pure functions over the shape the backend sends, so they can be tested
 * without a backend. What they pin is that every state the Rust side can produce has a
 * defined rendering and a defined answer to "is this connected" and "is this busy" — a
 * state that fell through would show as blank, or worse, as connected.
 */

import { describe, expect, it } from 'vitest';

import {
  type ConnectionState,
  connectionStateSchema,
  describeConnectionState,
  isBusy,
  isConnected,
} from './api.js';

/** One example of every state the backend can send. */
const everyState: ConnectionState[] = [
  { state: 'offline' },
  { state: 'connecting', address: '192.168.1.20:47811' },
  { state: 'authenticating' },
  {
    state: 'connected',
    sessionId: 'ses_abc',
    address: '192.168.1.20:47811',
    permissions: [],
    deviceName: 'Office PC',
  },
  { state: 'disconnecting' },
  { state: 'reconnecting', attempt: 3 },
  { state: 'waiting_to_retry', attempt: 4, retryInMs: 2500 },
  { state: 'refused', reason: 'identity_changed', message: 'The identity changed.' },
  { state: 'failed', message: 'Could not reach the server.' },
];

describe('connection state', () => {
  it('parses every state the backend can send', () => {
    for (const state of everyState) {
      expect(() => connectionStateSchema.parse(state)).not.toThrow();
    }
  });

  it('rejects a state the backend cannot produce', () => {
    // The schema parses rather than trusts, so an unexpected shape is a validation
    // error at the boundary and not a blank panel three components later.
    expect(() => connectionStateSchema.parse({ state: 'probably_fine' })).toThrow();
    expect(() => connectionStateSchema.parse({ state: 'connected' })).toThrow();
  });

  it('has no discovering state', () => {
    // `discovering` existed only for mDNS. Typing an address cannot discover, so the
    // schema at the IPC boundary must reject it rather than parse it through.
    expect(() => connectionStateSchema.parse({ state: 'discovering' })).toThrow();
  });

  it('describes every state a typed address can reach', () => {
    // One example of each of the nine states left once `discovering` is gone. Real
    // field values throughout, because this schema (unlike the brief's hypothetical
    // tag-only union) requires them: `refused` and `failed` render `state.message`
    // directly, so a placeholder object would make this pass for the wrong reason.
    for (const state of everyState) {
      expect(describeConnectionState(state)).toBeTruthy();
    }
  });

  it('describes every state without falling through to an empty string', () => {
    for (const state of everyState) {
      const described = describeConnectionState(state);
      expect(described.length).toBeGreaterThan(0);
    }
  });

  it('reports only a live session as connected', () => {
    for (const state of everyState) {
      expect(isConnected(state)).toBe(state.state === 'connected');
    }
  });

  it('reports the in-progress states as busy and the terminal ones as not', () => {
    // Busy states disable the buttons; getting this wrong either locks the UI or lets
    // an operator start a second connection over the top of the first.
    expect(isBusy({ state: 'connecting', address: 'x' })).toBe(true);
    expect(isBusy({ state: 'authenticating' })).toBe(true);
    expect(isBusy({ state: 'reconnecting', attempt: 1 })).toBe(true);
    expect(isBusy({ state: 'waiting_to_retry', attempt: 1, retryInMs: 10 })).toBe(true);

    expect(isBusy({ state: 'offline' })).toBe(false);
    expect(
      isBusy({ state: 'connected', sessionId: 's', address: 'x', permissions: [], deviceName: 'x' }),
    ).toBe(false);
    expect(isBusy({ state: 'failed', message: 'no' })).toBe(false);
    expect(isBusy({ state: 'refused', reason: 'not_authorized', message: 'no' })).toBe(false);
  });

  it('shows a refusal in the words the backend chose', () => {
    // The backend writes these messages because it knows which failure occurred; the
    // UI must not substitute a vaguer one of its own.
    const message = 'The server did not accept this device. Pair with it again.';
    expect(describeConnectionState({ state: 'refused', reason: 'not_authorized', message })).toBe(
      message,
    );
  });

  it('names the address in the connecting and connected states', () => {
    // An operator with two servers needs to know which one this is.
    expect(describeConnectionState({ state: 'connecting', address: '10.0.0.4:47811' })).toContain(
      '10.0.0.4:47811',
    );
    expect(
      describeConnectionState({
        state: 'connected',
        sessionId: 'ses_x',
        address: '10.0.0.4:47811',
        permissions: [],
        deviceName: 'Lab',
      }),
    ).toContain('10.0.0.4:47811');
  });

  it('renders the retry countdown in seconds rather than milliseconds', () => {
    expect(
      describeConnectionState({ state: 'waiting_to_retry', attempt: 2, retryInMs: 2500 }),
    ).toBe('Retrying in 2.5s…');
  });

  it('counts reconnect attempts for the operator', () => {
    expect(describeConnectionState({ state: 'reconnecting', attempt: 7 })).toContain('7');
  });

  it('never renders a session id as if it were a credential', () => {
    // The session id is an identifier for correlation, not a bearer value; showing it
    // in the status line would invite treating it as one.
    const described = describeConnectionState({
      state: 'connected',
      sessionId: 'ses_secret-looking-value',
      address: '10.0.0.4:47811',
      permissions: [],
      deviceName: 'Lab',
    });
    expect(described).not.toContain('ses_secret-looking-value');
  });
});
