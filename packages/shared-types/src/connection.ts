/**
 * Connection lifecycle: states, disconnect reasons, and the reconnection policy.
 *
 * The policy lives here rather than in the UI so it can be unit-tested in isolation,
 * and so the single most important rule in the whole application is stated in exactly
 * one place: **an intentional disconnect never triggers an automatic reconnect.**
 */

import { z } from 'zod';

/** Every state a connection can be in. Rendered verbatim in the connection bar. */
export const connectionStateSchema = z.enum([
  /** No connection, and none being attempted. */
  'offline',
  /** Searching the local network for the device. */
  'discovering',
  /** A transport connection is being established. */
  'connecting',
  /** Transport is up; identities are being verified. */
  'authenticating',
  /** Fully established and usable. */
  'connected',
  /** The connection dropped unexpectedly and is being retried. */
  'reconnecting',
  /** Credentials or device authorization were rejected. Terminal. */
  'auth_failed',
  /** The device presented a different identity than the pinned one. Terminal. */
  'identity_changed',
  /** The host was reachable but its agent did not answer. Terminal. */
  'agent_unavailable',
]);

export type ConnectionState = z.infer<typeof connectionStateSchema>;

/** States from which no further automatic progress will be made without the user. */
export const TERMINAL_STATES = [
  'auth_failed',
  'identity_changed',
  'agent_unavailable',
] as const satisfies readonly ConnectionState[];

/** Whether a state is terminal and requires explicit user action to leave. */
export function isTerminalState(state: ConnectionState): boolean {
  return (TERMINAL_STATES as readonly ConnectionState[]).includes(state);
}

/** Whether a state means a session is currently usable. */
export function isUsable(state: ConnectionState): boolean {
  return state === 'connected';
}

/** Whether a state represents work in progress, for spinner rendering. */
export function isBusy(state: ConnectionState): boolean {
  return state === 'discovering' || state === 'connecting' || state === 'authenticating';
}

/** Why a session ended. Mirrors the Rust `DisconnectReason`. */
export const disconnectReasonSchema = z.enum([
  'user_requested',
  'host_terminated',
  'session_expired',
  'idle_timeout',
  'agent_shutdown',
  'protocol_error',
  'transport_failure',
]);

export type DisconnectReason = z.infer<typeof disconnectReasonSchema>;

/**
 * Whether a reason permits automatic reconnection.
 *
 * This mirrors `DisconnectReason::permits_auto_reconnect` in the Rust protocol crate
 * exactly. If one side changes, the other must change with it — the paired tests in
 * `connection.test.ts` and `control.rs` both encode the same table.
 */
export function permitsAutoReconnect(reason: DisconnectReason): boolean {
  switch (reason) {
    case 'agent_shutdown':
    case 'transport_failure':
    case 'idle_timeout':
      return true;
    case 'user_requested':
    case 'host_terminated':
    case 'session_expired':
    case 'protocol_error':
      return false;
  }
}

/** How the transport reached the device, shown in the connection bar. */
export const networkModeSchema = z.enum([
  /** Direct connection over the local network. Preferred. */
  'lan_direct',
  /** Direct peer-to-peer connection established via NAT traversal. */
  'p2p',
  /** Traffic is passing through a relay. Still end-to-end encrypted. */
  'relay',
]);

export type NetworkMode = z.infer<typeof networkModeSchema>;

/** Tunable parameters for the reconnection backoff. */
export interface BackoffPolicy {
  /** Delay before the first retry, in milliseconds. */
  readonly initialDelayMs: number;
  /** Ceiling for the delay, in milliseconds. */
  readonly maxDelayMs: number;
  /** Multiplier applied after each failed attempt. */
  readonly multiplier: number;
  /**
   * Maximum proportion of the delay added or removed as random jitter, 0–1.
   *
   * Jitter matters because without it, a router reboot makes every saved device
   * retry in lockstep forever.
   */
  readonly jitterRatio: number;
  /** Give up after this many attempts. */
  readonly maxAttempts: number;
}

/** Default policy: fast first retry, backing off to 30s, giving up after 10 tries. */
export const DEFAULT_BACKOFF: BackoffPolicy = {
  initialDelayMs: 500,
  maxDelayMs: 30_000,
  multiplier: 2,
  jitterRatio: 0.2,
  maxAttempts: 10,
};

/**
 * Delay before retry number `attempt` (1-based), in milliseconds.
 *
 * Returns `null` when the policy says to stop trying. `random` is injected so the
 * result is deterministic under test; production callers omit it.
 */
export function nextRetryDelayMs(
  attempt: number,
  policy: BackoffPolicy = DEFAULT_BACKOFF,
  random: () => number = Math.random,
): number | null {
  if (attempt < 1 || attempt > policy.maxAttempts) return null;

  const exponential = policy.initialDelayMs * policy.multiplier ** (attempt - 1);
  const capped = Math.min(exponential, policy.maxDelayMs);

  // random() is in [0, 1); map to [-jitterRatio, +jitterRatio].
  const jitter = (random() * 2 - 1) * policy.jitterRatio;
  return Math.max(0, Math.round(capped * (1 + jitter)));
}

/** Inputs to the "should we reconnect?" decision. */
export interface ReconnectDecisionInput {
  /** Why the previous session ended. `null` if it never established. */
  readonly reason: DisconnectReason | null;
  /** How many automatic attempts have already been made. */
  readonly attempt: number;
  /** Whether the user has automatic reconnection enabled at all. */
  readonly autoReconnectEnabled: boolean;
  /** The policy in force. */
  readonly policy?: BackoffPolicy;
}

/** The outcome of the reconnection decision. */
export type ReconnectDecision =
  | { readonly kind: 'retry'; readonly delayMs: number }
  | { readonly kind: 'stop'; readonly why: ReconnectStopReason };

/** Why automatic reconnection will not be attempted. */
export type ReconnectStopReason =
  'user_disconnected' | 'auto_reconnect_disabled' | 'reason_forbids_retry' | 'attempts_exhausted';

/**
 * Decide whether to schedule another automatic reconnection attempt.
 *
 * The ordering of the checks is deliberate: the user's intent is consulted before
 * anything else, so no combination of settings or transport errors can override a
 * deliberate Disconnect.
 */
export function decideReconnect(
  input: ReconnectDecisionInput,
  random: () => number = Math.random,
): ReconnectDecision {
  // 1. An intentional disconnect wins over everything.
  if (input.reason === 'user_requested') {
    return { kind: 'stop', why: 'user_disconnected' };
  }
  // 2. Then the user's standing preference.
  if (!input.autoReconnectEnabled) {
    return { kind: 'stop', why: 'auto_reconnect_disabled' };
  }
  // 3. Then whether the reason itself is retryable.
  if (input.reason !== null && !permitsAutoReconnect(input.reason)) {
    return { kind: 'stop', why: 'reason_forbids_retry' };
  }
  // 4. Finally the attempt budget.
  const policy = input.policy ?? DEFAULT_BACKOFF;
  const delayMs = nextRetryDelayMs(input.attempt, policy, random);
  if (delayMs === null) {
    return { kind: 'stop', why: 'attempts_exhausted' };
  }
  return { kind: 'retry', delayMs };
}
