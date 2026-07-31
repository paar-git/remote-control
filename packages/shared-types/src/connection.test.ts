import { describe, expect, it } from 'vitest';

import {
  DEFAULT_BACKOFF,
  type DisconnectReason,
  decideReconnect,
  isBusy,
  isTerminalState,
  isUsable,
  nextRetryDelayMs,
  permitsAutoReconnect,
} from './connection.js';

/** Deterministic "random" for jitter, so delays are exact under test. */
const noJitter = (): number => 0.5;

describe('connection states', () => {
  it('treats only `connected` as usable', () => {
    expect(isUsable('connected')).toBe(true);
    for (const state of ['offline', 'connecting', 'authenticating', 'reconnecting'] as const) {
      expect(isUsable(state), state).toBe(false);
    }
  });

  it('marks authentication and identity failures as terminal', () => {
    expect(isTerminalState('auth_failed')).toBe(true);
    expect(isTerminalState('identity_changed')).toBe(true);
    expect(isTerminalState('agent_unavailable')).toBe(true);
    expect(isTerminalState('reconnecting')).toBe(false);
  });

  it('marks in-progress states as busy', () => {
    expect(isBusy('discovering')).toBe(true);
    expect(isBusy('connecting')).toBe(true);
    expect(isBusy('authenticating')).toBe(true);
    expect(isBusy('connected')).toBe(false);
  });
});

describe('disconnect reasons', () => {
  it('never permits auto-reconnect after an intentional disconnect', () => {
    expect(permitsAutoReconnect('user_requested')).toBe(false);
    expect(permitsAutoReconnect('host_terminated')).toBe(false);
  });

  it('never permits auto-reconnect after an authorization failure', () => {
    expect(permitsAutoReconnect('session_expired')).toBe(false);
    expect(permitsAutoReconnect('protocol_error')).toBe(false);
  });

  it('permits auto-reconnect after a transport failure', () => {
    expect(permitsAutoReconnect('transport_failure')).toBe(true);
    expect(permitsAutoReconnect('agent_shutdown')).toBe(true);
    expect(permitsAutoReconnect('idle_timeout')).toBe(true);
  });

  it('matches the Rust table exactly', () => {
    // Mirrors `DisconnectReason::permits_auto_reconnect` in crates/protocol.
    const expected: Record<DisconnectReason, boolean> = {
      user_requested: false,
      host_terminated: false,
      session_expired: false,
      protocol_error: false,
      agent_shutdown: true,
      transport_failure: true,
      idle_timeout: true,
    };
    for (const [reason, allowed] of Object.entries(expected)) {
      expect(permitsAutoReconnect(reason as DisconnectReason), reason).toBe(allowed);
    }
  });
});

describe('backoff', () => {
  it('grows exponentially', () => {
    expect(nextRetryDelayMs(1, DEFAULT_BACKOFF, noJitter)).toBe(500);
    expect(nextRetryDelayMs(2, DEFAULT_BACKOFF, noJitter)).toBe(1000);
    expect(nextRetryDelayMs(3, DEFAULT_BACKOFF, noJitter)).toBe(2000);
    expect(nextRetryDelayMs(4, DEFAULT_BACKOFF, noJitter)).toBe(4000);
  });

  it('is capped at the maximum delay', () => {
    for (const attempt of [8, 9, 10]) {
      const delay = nextRetryDelayMs(attempt, DEFAULT_BACKOFF, noJitter);
      expect(delay).toBeLessThanOrEqual(DEFAULT_BACKOFF.maxDelayMs);
    }
    expect(nextRetryDelayMs(10, DEFAULT_BACKOFF, noJitter)).toBe(DEFAULT_BACKOFF.maxDelayMs);
  });

  it('returns null past the attempt budget', () => {
    expect(nextRetryDelayMs(DEFAULT_BACKOFF.maxAttempts, DEFAULT_BACKOFF, noJitter)).not.toBeNull();
    expect(nextRetryDelayMs(DEFAULT_BACKOFF.maxAttempts + 1, DEFAULT_BACKOFF, noJitter)).toBeNull();
    expect(nextRetryDelayMs(0, DEFAULT_BACKOFF, noJitter)).toBeNull();
  });

  it('applies jitter within the configured band and never goes negative', () => {
    const lowest = nextRetryDelayMs(3, DEFAULT_BACKOFF, () => 0);
    const highest = nextRetryDelayMs(3, DEFAULT_BACKOFF, () => 0.999999);

    expect(lowest).toBe(1600); // 2000 * (1 - 0.2)
    expect(highest).toBeGreaterThan(2000);
    expect(highest).toBeLessThanOrEqual(2400); // 2000 * (1 + 0.2)
    expect(lowest).toBeGreaterThanOrEqual(0);
  });

  it('produces spread-out delays across many clients', () => {
    // Without jitter every device would retry in lockstep after a router reboot.
    const delays = new Set(Array.from({ length: 50 }, () => nextRetryDelayMs(5, DEFAULT_BACKOFF)));
    expect(delays.size).toBeGreaterThan(1);
  });
});

describe('reconnect decision', () => {
  const base = { attempt: 1, autoReconnectEnabled: true } as const;

  it('refuses to reconnect after the user pressed Disconnect', () => {
    const decision = decideReconnect({ ...base, reason: 'user_requested' }, noJitter);
    expect(decision).toEqual({ kind: 'stop', why: 'user_disconnected' });
  });

  it('refuses even when auto-reconnect is enabled and attempts remain', () => {
    // The user's intent must dominate every other input.
    const decision = decideReconnect(
      { reason: 'user_requested', attempt: 1, autoReconnectEnabled: true },
      noJitter,
    );
    expect(decision.kind).toBe('stop');
  });

  it('retries after an unexpected transport failure', () => {
    const decision = decideReconnect({ ...base, reason: 'transport_failure' }, noJitter);
    expect(decision).toEqual({ kind: 'retry', delayMs: 500 });
  });

  it('retries when the session never established', () => {
    const decision = decideReconnect({ ...base, reason: null }, noJitter);
    expect(decision.kind).toBe('retry');
  });

  it('honours the auto-reconnect preference', () => {
    const decision = decideReconnect(
      { reason: 'transport_failure', attempt: 1, autoReconnectEnabled: false },
      noJitter,
    );
    expect(decision).toEqual({ kind: 'stop', why: 'auto_reconnect_disabled' });
  });

  it('stops for reasons that forbid retrying', () => {
    for (const reason of ['session_expired', 'protocol_error', 'host_terminated'] as const) {
      const decision = decideReconnect({ ...base, reason }, noJitter);
      expect(decision, reason).toEqual({ kind: 'stop', why: 'reason_forbids_retry' });
    }
  });

  it('gives up once the attempt budget is exhausted', () => {
    const decision = decideReconnect(
      {
        reason: 'transport_failure',
        attempt: DEFAULT_BACKOFF.maxAttempts + 1,
        ...{ autoReconnectEnabled: true },
      },
      noJitter,
    );
    expect(decision).toEqual({ kind: 'stop', why: 'attempts_exhausted' });
  });

  it('backs off further with each successive attempt', () => {
    const delays = [1, 2, 3, 4].map((attempt) => {
      const decision = decideReconnect(
        { reason: 'transport_failure', attempt, autoReconnectEnabled: true },
        noJitter,
      );
      return decision.kind === 'retry' ? decision.delayMs : -1;
    });
    expect(delays).toEqual([500, 1000, 2000, 4000]);
  });
});
