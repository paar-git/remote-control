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

/* -------------------------------------------------------------------------- */
/* Monitoring                                                                 */
/* -------------------------------------------------------------------------- */

/** One mounted volume on the server. */
export const diskSchema = z.object({
  mountPoint: untrustedText(260),
  filesystem: untrustedText(32),
  totalBytes: z.number().nonnegative(),
  availableBytes: z.number().nonnegative(),
});

/** One network interface on the server. */
export const networkSchema = z.object({
  interface: untrustedText(64),
  receiveRateBps: z.number().nonnegative(),
  transmitRateBps: z.number().nonnegative(),
  receivedBytes: z.number().nonnegative(),
  transmittedBytes: z.number().nonnegative(),
});

/** One temperature sensor. */
export const temperatureSchema = z.object({
  label: untrustedText(64),
  celsius: z.number(),
  criticalCelsius: z.number().nullable(),
});

/** One process on the server. */
export const processSchema = z.object({
  pid: z.number().int().nonnegative(),
  name: untrustedText(128),
  user: untrustedText(64).nullable(),
  cpuPercent: z.number(),
  memoryBytes: z.number().nonnegative(),
});

/**
 * A live reading from the server.
 *
 * An empty `temperatures` means no sensor was readable, not that the machine is cold.
 * There is deliberately no field for a GPU or a battery: the agent does not measure
 * either, and a field would invite showing a figure it never produced.
 */
export const snapshotSchema = z.object({
  capturedAtMs: z.number().int(),
  uptimeSecs: z.number().nonnegative(),
  cpuModel: untrustedText(128),
  cpuPercent: z.number(),
  cpuPerCore: z.array(z.number()),
  logicalCores: z.number().int().nonnegative(),
  memoryUsedBytes: z.number().nonnegative(),
  memoryTotalBytes: z.number().nonnegative(),
  swapUsedBytes: z.number().nonnegative(),
  swapTotalBytes: z.number().nonnegative(),
  disks: z.array(diskSchema),
  networks: z.array(networkSchema),
  temperatures: z.array(temperatureSchema),
  topProcesses: z.array(processSchema),
  loadAverage: z.tuple([z.number(), z.number(), z.number()]).nullable(),
});

export type Snapshot = z.infer<typeof snapshotSchema>;

/** Facts about the server that do not change between readings. */
export const serverFactsSchema = z.object({
  hostname: untrustedText(253),
  osFamily: z.enum(['windows', 'linux', 'macos', 'unknown']),
  osVersion: untrustedText(128),
  kernelVersion: untrustedText(128),
  architecture: untrustedText(32),
  logicalCores: z.number().int().nonnegative(),
  agentVersion: untrustedText(32),
  agentUser: untrustedText(64),
  agentElevated: z.boolean(),
  bootedAtMs: z.number().int(),
});

export type ServerFacts = z.infer<typeof serverFactsSchema>;

/** Fetch a live reading from the connected server. */
export function getSystemSnapshot(): Promise<Snapshot> {
  return call('system_snapshot', snapshotSchema);
}

/** Fetch the server facts that do not change between readings. */
export function getServerFacts(): Promise<ServerFacts> {
  return call('server_facts', serverFactsSchema);
}

/* -------------------------------------------------------------------------- */
/* Terminal                                                                   */
/* -------------------------------------------------------------------------- */

/** A terminal that opened on the server. */
export const openedTerminalSchema = z.object({
  terminalId: z.string().min(1),
  shellPath: untrustedText(512),
  pid: z.number().int().nonnegative(),
  elevated: z.boolean(),
});

export type OpenedTerminal = z.infer<typeof openedTerminalSchema>;

/** Open a terminal on the connected server. */
export function openTerminal(
  shell: string,
  cols: number,
  rows: number,
  workingDirectory: string | null = null,
): Promise<OpenedTerminal> {
  return call('open_terminal', openedTerminalSchema, {
    input: { shell, cols, rows, workingDirectory },
  });
}

/**
 * Send keystrokes to a terminal.
 *
 * Encoded to UTF-8 and then base64 because the transport carries bytes, not strings.
 * A terminal's input is not text in general — it includes control characters and the
 * emulator's own replies to the shell's queries — and treating it as text would mangle
 * anything that is not.
 */
export function sendTerminalInput(terminalId: string, data: string): Promise<null> {
  return call('send_terminal_input', z.null(), {
    terminalId,
    dataBase64: bytesToBase64(new TextEncoder().encode(data)),
  });
}

/** Tell the server the terminal window changed size. */
export function resizeTerminal(terminalId: string, cols: number, rows: number): Promise<null> {
  return call('resize_terminal', z.null(), { terminalId, cols, rows });
}

/** Close a terminal. */
export function closeTerminal(terminalId: string): Promise<null> {
  return call('close_terminal', z.null(), { terminalId });
}

/** One chunk of terminal output, already decoded. */
export interface TerminalOutput {
  readonly terminalId: string;
  /** The bytes the shell wrote, as a binary string the emulator consumes. */
  readonly data: string;
}

/** A terminal that ended. */
export interface TerminalExit {
  readonly terminalId: string;
  readonly exitCode: number | null;
  readonly error: string | null;
}

const terminalOutputEventSchema = z.object({
  terminalId: z.string().min(1),
  dataBase64: z.string(),
});

const terminalExitEventSchema = z.object({
  terminalId: z.string().min(1),
  exitCode: z.number().int().nullable(),
  error: z.string().nullable(),
});

/**
 * Subscribe to terminal output.
 *
 * Returns the unlisten function, as Tauri's event API does.
 */
export async function listenTerminalOutput(
  handler: (output: TerminalOutput) => void,
): Promise<() => void> {
  const { listen } = await import('@tauri-apps/api/event');

  return listen('terminal://output', (event) => {
    const parsed = terminalOutputEventSchema.safeParse(event.payload);
    if (!parsed.success) return;

    handler({
      terminalId: parsed.data.terminalId,
      // A binary string, one character per byte. A UTF-8 decode here would corrupt a
      // multi-byte character split across two chunks; the emulator reassembles them.
      data: base64ToBinaryString(parsed.data.dataBase64),
    });
  });
}

/** Subscribe to terminal exits and failures. */
export async function listenTerminalExit(
  handler: (exit: TerminalExit) => void,
): Promise<() => void> {
  const { listen } = await import('@tauri-apps/api/event');

  return listen('terminal://exit', (event) => {
    const parsed = terminalExitEventSchema.safeParse(event.payload);
    if (parsed.success) handler(parsed.data);
  });
}

/** Encode bytes as base64. */
function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

/** Decode base64 into a binary string, one character per byte. */
function base64ToBinaryString(encoded: string): string {
  return atob(encoded);
}
