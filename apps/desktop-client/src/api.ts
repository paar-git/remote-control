/**
 * Typed wrappers around the backend commands the client exposes.
 *
 * Each wrapper pairs a command name with the schema its response must satisfy.
 * Nothing here type-asserts: a backend that returns an unexpected shape produces a
 * validation error rather than a runtime surprise deeper in the UI.
 */

import { fingerprintSchema, protocolVersionSchema, untrustedText } from '@rc/shared-types';
import { z } from 'zod';

import { call } from './ipc.js';

/* -------------------------------------------------------------------------- */
/* Client and identity                                                        */
/* -------------------------------------------------------------------------- */

/** Information the backend reports about itself and the machine it runs on. */
export const clientInfoSchema = z.object({
  appVersion: z.string().min(1),
  protocolVersion: protocolVersionSchema,
  hostname: z.string(),
  osFamily: z.enum(['windows', 'linux', 'macos', 'unknown']),
  osVersion: z.string(),
  architecture: z.string(),
  /** Whether this process holds Administrator/root. Expected to be `false`. */
  elevated: z.boolean(),
  /** Whether the client's database opened and migrated successfully. */
  databaseReady: z.boolean(),
});

export type ClientInfo = z.infer<typeof clientInfoSchema>;

/** Fetch information about the client backend. */
export function getClientInfo(): Promise<ClientInfo> {
  return call('client_info', clientInfoSchema);
}

/** This client's own cryptographic identity. */
export const localIdentitySchema = z.object({
  deviceId: z.string().min(1),
  /** The value a paired agent pins. Stable across certificate renewal. */
  identityFingerprint: fingerprintSchema,
  /** The current credential. Expected to change when the certificate renews. */
  certificateFingerprint: fingerprintSchema,
  certificateVersion: z.number().int().nonnegative(),
  certificateNotBeforeMs: z.number().int(),
  certificateNotAfterMs: z.number().int(),
  needsRenewal: z.boolean(),
});

export type LocalIdentity = z.infer<typeof localIdentitySchema>;

/** Fetch this client's identity. */
export function getLocalIdentity(): Promise<LocalIdentity> {
  return call('local_identity', localIdentitySchema);
}

/* -------------------------------------------------------------------------- */
/* Owner account                                                              */
/* -------------------------------------------------------------------------- */

/** Whether an owner account exists and whether the app is unlocked. */
export const ownerStatusSchema = z.object({
  accountExists: z.boolean(),
  authenticated: z.boolean(),
  username: z.string().nullable(),
});

export type OwnerStatus = z.infer<typeof ownerStatusSchema>;

/** Fetch the owner-account status. */
export function getOwnerStatus(): Promise<OwnerStatus> {
  return call('owner_status', ownerStatusSchema);
}

/** Create the owner account. Only valid on first run. */
export function createOwner(username: string, password: string): Promise<null> {
  return call('create_owner', z.null(), { credentials: { username, password } });
}

/** Authenticate and unlock the application. */
export function ownerLogin(username: string, password: string): Promise<OwnerStatus> {
  return call('owner_login', ownerStatusSchema, { credentials: { username, password } });
}

/** Lock the application. */
export function ownerLogout(): Promise<null> {
  return call('owner_logout', z.null());
}

/* -------------------------------------------------------------------------- */
/* Trusted devices                                                            */
/* -------------------------------------------------------------------------- */

/** Permission roles, mirroring the Rust `Role`. */
export const roleSchema = z.enum(['owner', 'view_only', 'operator']);
export type DeviceRole = z.infer<typeof roleSchema>;

/** Human labels for roles. */
export const ROLE_LABELS: Record<DeviceRole, string> = {
  owner: 'Owner',
  view_only: 'View only',
  operator: 'Operator',
};

/**
 * A trusted device.
 *
 * `displayName` and `hostname` originate on a remote machine, so they are passed
 * through `untrustedText` to strip control characters and bidirectional overrides
 * before they are ever rendered.
 */
export const trustedDeviceSchema = z.object({
  deviceId: z.string().min(1),
  displayName: untrustedText(128),
  hostname: untrustedText(253),
  identityFingerprint: fingerprintSchema,
  certificateFingerprint: fingerprintSchema,
  role: roleSchema,
  capabilities: z.array(z.string()),
  pairedAtMs: z.number().int(),
  lastAuthenticatedAtMs: z.number().int().nullable(),
  revoked: z.boolean(),
  revokedAtMs: z.number().int().nullable(),
});

export type TrustedDevice = z.infer<typeof trustedDeviceSchema>;

/** List trusted devices. */
export function listTrustedDevices(): Promise<TrustedDevice[]> {
  return call('list_trusted_devices', z.array(trustedDeviceSchema));
}

/** Rename a trusted device. */
export function renameTrustedDevice(deviceId: string, newName: string): Promise<null> {
  return call('rename_trusted_device', z.null(), { deviceId, newName });
}

/** Revoke a trusted device. Takes effect immediately. */
export function revokeTrustedDevice(deviceId: string): Promise<null> {
  return call('revoke_trusted_device', z.null(), { deviceId });
}

/* -------------------------------------------------------------------------- */
/* Audit                                                                      */
/* -------------------------------------------------------------------------- */

/** One audit-log entry. */
export const auditEntrySchema = z.object({
  id: z.number().int(),
  occurredAtMs: z.number().int(),
  category: z.string(),
  action: z.string(),
  result: z.enum(['success', 'failure', 'denied']),
  targetDeviceId: z.string().nullable(),
});

export type AuditEntry = z.infer<typeof auditEntrySchema>;

/** Fetch recent audit entries. */
export function getRecentAuditEvents(limit = 50): Promise<AuditEntry[]> {
  return call('recent_audit_events', z.array(auditEntrySchema), { limit });
}

/* -------------------------------------------------------------------------- */
/* Pairing                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Check that a typed pairing code *could* be a code.
 *
 * Format only. It gives immediate feedback while the operator types; it proves
 * nothing about whether the code is correct, which only the server can decide.
 */
export function checkPairingCodeFormat(code: string): Promise<boolean> {
  return call('check_pairing_code_format', z.boolean(), { code });
}

/**
 * A server seen on the local network.
 *
 * Every field here is **untrusted**: anyone on the LAN can broadcast an announcement
 * claiming any device id and name. It is shown so the operator can pick a machine to
 * pair with; the connection that follows authenticates regardless. `claimedFingerprint`
 * is named for what it is, and is never treated as the pinned value.
 */
export const discoveredAgentSchema = z.object({
  deviceId: z.string().min(1),
  displayName: untrustedText(64),
  address: z.string().min(1),
  claimedFingerprint: z.string().nullable(),
  alreadySaved: z.boolean(),
});

export type DiscoveredAgent = z.infer<typeof discoveredAgentSchema>;

/** Search the local network for servers. An empty list is a normal outcome. */
export function discoverAgents(): Promise<DiscoveredAgent[]> {
  return call('discover_agents', z.array(discoveredAgentSchema));
}

/** What a completed pairing produced. */
export const pairedServerSchema = z.object({
  deviceId: z.string().min(1),
  displayName: untrustedText(128),
  /** Grouped for reading aloud against what the server printed. */
  identityFingerprint: z.string().min(1),
  role: roleSchema,
});

export type PairedServer = z.infer<typeof pairedServerSchema>;

/**
 * Pair with a server and save it.
 *
 * The code is sent to the backend and is never returned, logged or stored. It is used
 * once to derive a proof and then dropped.
 */
export function pairWithServer(
  address: string,
  code: string,
  displayName: string,
): Promise<PairedServer> {
  return call('pair_with_server', pairedServerSchema, {
    input: { address, code, displayName },
  });
}

/* -------------------------------------------------------------------------- */
/* Connection                                                                 */
/* -------------------------------------------------------------------------- */

/** Why a server refused this device, as far as the client can tell. */
export const refusalReasonSchema = z.enum([
  'identity_changed',
  'not_authorized',
  'protocol_mismatch',
  'throttled',
]);

export type RefusalReason = z.infer<typeof refusalReasonSchema>;

/**
 * Where the connection is in its lifecycle.
 *
 * A discriminated union on `state`, so the UI switches on one field rather than
 * inferring the situation from a combination of booleans.
 */
export const connectionStateSchema = z.discriminatedUnion('state', [
  z.object({ state: z.literal('offline') }),
  z.object({ state: z.literal('discovering') }),
  z.object({ state: z.literal('connecting'), address: z.string() }),
  z.object({ state: z.literal('authenticating') }),
  z.object({
    state: z.literal('connected'),
    sessionId: z.string(),
    address: z.string(),
  }),
  z.object({ state: z.literal('disconnecting') }),
  z.object({ state: z.literal('reconnecting'), attempt: z.number().int() }),
  z.object({
    state: z.literal('waiting_to_retry'),
    attempt: z.number().int(),
    retryInMs: z.number().int(),
  }),
  z.object({
    state: z.literal('refused'),
    reason: refusalReasonSchema,
    message: z.string(),
  }),
  z.object({ state: z.literal('failed'), message: z.string() }),
]);

export type ConnectionState = z.infer<typeof connectionStateSchema>;

/** Human labels for each connection state. */
export function describeConnectionState(state: ConnectionState): string {
  switch (state.state) {
    case 'offline':
      return 'Not connected';
    case 'discovering':
      return 'Searching the local network…';
    case 'connecting':
      return `Connecting to ${state.address}…`;
    case 'authenticating':
      return 'Verifying the server’s identity…';
    case 'connected':
      return `Connected — ${state.address}`;
    case 'disconnecting':
      return 'Disconnecting…';
    case 'reconnecting':
      return `Reconnecting (attempt ${String(state.attempt)})…`;
    case 'waiting_to_retry':
      return `Retrying in ${String(Math.round(state.retryInMs / 100) / 10)}s…`;
    case 'refused':
      return state.message;
    case 'failed':
      return state.message;
  }
}

/** Whether a state means a live, usable session. */
export function isConnected(state: ConnectionState): boolean {
  return state.state === 'connected';
}

/** Whether a state means something is in progress. */
export function isBusy(state: ConnectionState): boolean {
  return (
    state.state === 'discovering' ||
    state.state === 'connecting' ||
    state.state === 'authenticating' ||
    state.state === 'disconnecting' ||
    state.state === 'reconnecting' ||
    state.state === 'waiting_to_retry'
  );
}

/** Connect to a saved server. */
export function connectToServer(deviceId: string): Promise<ConnectionState> {
  return call('connect_to_server', connectionStateSchema, { deviceId });
}

/** Disconnect deliberately. Suppresses automatic reconnection. */
export function disconnectFromServer(): Promise<ConnectionState> {
  return call('disconnect_from_server', connectionStateSchema);
}

/** Reconnect to a saved server, applying the backoff. */
export function reconnectToServer(deviceId: string): Promise<ConnectionState> {
  return call('reconnect_to_server', connectionStateSchema, { deviceId });
}

/** The current connection state. */
export function getConnectionState(): Promise<ConnectionState> {
  return call('connection_state', connectionStateSchema);
}

/** Measure the round trip to the connected server, in milliseconds. */
export function pingServer(): Promise<number> {
  return call('ping_server', z.number().int().nonnegative());
}
