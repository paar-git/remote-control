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

/**
 * One pushed reading.
 *
 * Deliberately a subset of {@link snapshotSchema}: the fields that change between
 * samples. The process list and the CPU model come from a snapshot, once — sending them
 * every tick would make fixed facts look like live readings, and would make a dashboard
 * cost a full process walk several times a minute on the server it is watching.
 */
export const metricsTickSchema = z.object({
  capturedAtMs: z.number().int(),
  uptimeSecs: z.number().nonnegative(),
  cpuPercent: z.number(),
  cpuPerCore: z.array(z.number()),
  memoryUsedBytes: z.number().nonnegative(),
  memoryTotalBytes: z.number().nonnegative(),
  swapUsedBytes: z.number().nonnegative(),
  swapTotalBytes: z.number().nonnegative(),
  disks: z.array(diskSchema),
  networks: z.array(networkSchema),
  temperatures: z.array(temperatureSchema),
  loadAverage: z.tuple([z.number(), z.number(), z.number()]).nullable(),
});

export type MetricsTick = z.infer<typeof metricsTickSchema>;

/** Why a metrics stream ended. */
export const metricsStoppedSchema = z.object({
  reason: z.string().min(1),
  message: untrustedText(256),
});

export type MetricsStopped = z.infer<typeof metricsStoppedSchema>;

/**
 * Ask the server to push readings.
 *
 * Resolves to the interval the server actually accepted, which may be slower than the
 * one requested — so a screen reports the rate it is getting rather than the rate it
 * hoped for.
 */
export function subscribeMetrics(intervalMs: number): Promise<number> {
  return call('subscribe_metrics', z.number().int().positive(), { input: { intervalMs } });
}

/** Ask the server to stop pushing readings. */
export function unsubscribeMetrics(): Promise<void> {
  return call('unsubscribe_metrics', z.void());
}

/**
 * Subscribe to pushed readings.
 *
 * Returns the unlisten function, as Tauri's event API does.
 */
export async function listenMetricsUpdate(
  handler: (tick: MetricsTick) => void,
): Promise<() => void> {
  const { listen } = await import('@tauri-apps/api/event');

  return listen('metrics://update', (event) => {
    const parsed = metricsTickSchema.safeParse(event.payload);
    if (parsed.success) handler(parsed.data);
  });
}

/**
 * Subscribe to the end of a metrics stream.
 *
 * Worth listening for rather than assuming silence means idle: a dashboard that stopped
 * being updated must say so instead of leaving its last reading on screen looking
 * current.
 */
export async function listenMetricsStopped(
  handler: (stopped: MetricsStopped) => void,
): Promise<() => void> {
  const { listen } = await import('@tauri-apps/api/event');

  return listen('metrics://stopped', (event) => {
    const parsed = metricsStoppedSchema.safeParse(event.payload);
    if (parsed.success) handler(parsed.data);
  });
}

/* -------------------------------------------------------------------------- */
/* Files                                                                      */
/* -------------------------------------------------------------------------- */

/** What a directory entry is. */
export const entryKindSchema = z.enum(['file', 'directory', 'symlink', 'other']);
export type EntryKind = z.infer<typeof entryKindSchema>;

/**
 * One entry in a file listing.
 *
 * `name` and `symlinkTarget` originate on a remote machine — or on this one, from a
 * directory anyone could have written to — so both go through `untrustedText`, which
 * strips control characters and bidirectional overrides before anything renders them.
 * Without that, a file called `co<U+202E>gnp.exe` displays as `codexe.png`.
 */
export const fileEntrySchema = z.object({
  name: untrustedText(255),
  kind: entryKindSchema,
  sizeBytes: z.number().nonnegative(),
  modifiedMs: z.number().int().nullable(),
  hidden: z.boolean(),
  readable: z.boolean(),
  writable: z.boolean(),
  permissions: untrustedText(32),
  symlinkTarget: untrustedText(4096).nullable(),
});

export type FileEntry = z.infer<typeof fileEntrySchema>;

/** A directory listing. */
export const listingSchema = z.object({
  /** The path actually listed, after the server resolved it. */
  path: untrustedText(4096),
  entries: z.array(fileEntrySchema),
  truncated: z.boolean(),
});

export type Listing = z.infer<typeof listingSchema>;

/** How a transfer ended. */
export const transferResultSchema = z.object({
  bytesTransferred: z.number().nonnegative(),
  path: untrustedText(4096),
});

export type TransferResult = z.infer<typeof transferResultSchema>;

/** What to do when the destination already exists. */
export type ConflictChoice = 'fail' | 'overwrite' | 'resume' | 'rename';

/** List a directory on the connected server. */
export function listRemoteDirectory(path: string, includeHidden: boolean): Promise<Listing> {
  return call('list_remote_directory', listingSchema, { path, includeHidden });
}

/** List a directory on this machine. */
export function listLocalDirectory(path: string, includeHidden: boolean): Promise<Listing> {
  return call('list_local_directory', listingSchema, { path, includeHidden });
}

/** The directory the local pane opens on. */
export function getDefaultLocalDirectory(): Promise<string> {
  return call('default_local_directory', z.string().min(1));
}

/** Create a directory on the server. */
export function createRemoteDirectory(path: string): Promise<null> {
  return call('create_remote_directory', z.null(), { path });
}

/**
 * Delete a path on the server.
 *
 * There is no recycle bin: this is permanent, and the confirmation dialog says so.
 */
export function deleteRemotePath(path: string, recursive: boolean): Promise<null> {
  return call('delete_remote_path', z.null(), { path, recursive });
}

/** Rename or move a path on the server. */
export function renameRemotePath(from: string, to: string): Promise<null> {
  return call('rename_remote_path', z.null(), { from, to });
}

/**
 * Upload a local file to the server.
 *
 * The bytes never pass through the webview — the backend reads the file and streams it.
 * This call therefore takes as long as the transfer does.
 */
export function uploadFile(
  localPath: string,
  remotePath: string,
  conflict: ConflictChoice,
): Promise<TransferResult> {
  return call('upload_file', transferResultSchema, {
    input: { localPath, remotePath, conflict },
  });
}

/** Download a file from the server to this machine. */
export function downloadFile(
  localPath: string,
  remotePath: string,
  conflict: ConflictChoice,
): Promise<TransferResult> {
  return call('download_file', transferResultSchema, {
    input: { localPath, remotePath, conflict },
  });
}

/**
 * Join a directory and a name into a path for the given platform.
 *
 * Done here rather than by string concatenation at each call site because the two
 * panes can be on different platforms — a Windows client browsing a Linux server is the
 * ordinary case — and the separator has to follow the *pane*, not this machine.
 */
export function joinPath(directory: string, name: string): string {
  const windows = directory.includes('\\') || /^[A-Za-z]:$/.test(directory);
  const separator = windows ? '\\' : '/';
  const trimmed = directory.endsWith(separator) ? directory.slice(0, -1) : directory;
  return `${trimmed}${separator}${name}`;
}

/**
 * The parent of a path, or `null` at the root.
 *
 * Returning `null` rather than the path itself is what lets the UI disable "up" at the
 * top instead of offering a button that does nothing.
 */
export function parentPath(path: string): string | null {
  const windows = path.includes('\\');
  const separator = windows ? '\\' : '/';

  // The POSIX root is its own trimmed form, and it has no parent. Returning it would
  // give the UI an "up" button that appears live and does nothing.
  if (path === '/') return null;

  const trimmed = path.endsWith(separator) && path.length > 1 ? path.slice(0, -1) : path;
  const cut = trimmed.lastIndexOf(separator);
  if (cut < 0) return null;

  // A POSIX top-level directory's parent is the root itself.
  if (cut === 0) return windows ? null : '/';

  // A Windows drive root is `C:\`, not `C:` — the latter means "the working directory
  // on drive C", which is not what clicking "up" is asking for.
  const parent = trimmed.slice(0, cut);
  return /^[A-Za-z]:$/.test(parent) ? `${parent}\\` : parent;
}

/* -------------------------------------------------------------------------- */
/* Updates                                                                    */
/* -------------------------------------------------------------------------- */

export const updateStateSchema = z.enum([
  'idle',
  'checking_for_updates',
  'no_update_available',
  'update_available',
  'preparing_download',
  'downloading',
  'paused',
  'waiting_for_network',
  'resuming',
  'verifying',
  'ready_to_install',
  'waiting_for_user_confirmation',
  'installing',
  'restart_required',
  'completed',
  'failed',
  'recovering',
]);
export type UpdateState = z.infer<typeof updateStateSchema>;

export const downloadQueueStateSchema = z.enum([
  'queued',
  'downloading',
  'paused',
  'waiting_for_network',
  'completed',
  'failed',
  'cancelled',
]);

export const packageFormatSchema = z.enum([
  'exe',
  'msi',
  'dmg',
  'pkg',
  'appimage',
  'deb',
  'rpm',
  'tar.gz',
]);
export type PackageFormat = z.infer<typeof packageFormatSchema>;

export const updatePlatformSchema = z.object({
  os: z.enum(['windows', 'macos', 'linux']),
  osVersion: z.string(),
  cpuArchitecture: z.enum(['x64', 'arm64']),
  installationArchitecture: z.enum(['x64', 'arm64']),
  key: z.string().min(1),
  osBuild: z.number().int().nonnegative().nullable().optional(),
  linuxKernelVersion: z.string().nullable().optional(),
  linuxGlibcVersion: z.string().nullable().optional(),
  linuxDistribution: z.string().nullable().optional(),
  installationType: z.enum([
    'windows-msi',
    'windows-exe',
    'macos-app-bundle',
    'macos-pkg',
    'linux-deb',
    'linux-rpm',
    'linux-app-image',
    'portable-archive',
    'unknown',
  ]),
});

export const downloadProgressSchema = z.object({
  key: z.string().min(1),
  state: downloadQueueStateSchema,
  downloadedBytes: z.number().int().nonnegative(),
  totalBytes: z.number().int().nonnegative(),
  percent: z.number().min(0).max(100),
  retryCount: z.number().int().nonnegative(),
});
export type DownloadProgress = z.infer<typeof downloadProgressSchema>;

export const updateStatusSchema = z.object({
  state: updateStateSchema,
  manifestUrl: z.string().nullable(),
  currentVersion: z.string().min(1),
  availableVersion: z.string().nullable(),
  releaseNotes: z.string().nullable(),
  platform: updatePlatformSchema,
  packageFormat: packageFormatSchema.nullable(),
  download: downloadProgressSchema.nullable(),
  readyPath: z.string().nullable(),
  lastError: z.string().nullable(),
});
export type UpdateStatus = z.infer<typeof updateStatusSchema>;

export const installResultSchema = z.object({
  restartRequired: z.boolean(),
  message: z.string().min(1),
});
export type InstallResult = z.infer<typeof installResultSchema>;

export function getUpdateStatus(): Promise<UpdateStatus> {
  return call('update_status', updateStatusSchema);
}

export function checkForUpdates(manifestUrl: string | null): Promise<UpdateStatus> {
  return call('check_for_updates', updateStatusSchema, { request: { manifestUrl } });
}

export function downloadUpdate(): Promise<UpdateStatus> {
  return call('download_update', updateStatusSchema);
}

export function pauseUpdateDownload(): Promise<UpdateStatus> {
  return call('pause_update_download', updateStatusSchema);
}

export function resumeUpdateDownload(): Promise<UpdateStatus> {
  return call('resume_update_download', updateStatusSchema);
}

export function cancelUpdateDownload(deletePartial: boolean): Promise<UpdateStatus> {
  return call('cancel_update_download', updateStatusSchema, { deletePartial });
}

export function installUpdate(): Promise<InstallResult> {
  return call('install_update', installResultSchema);
}
