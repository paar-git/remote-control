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

/**
 * A permission a session can hold. These exact strings are `Permission::name()` in
 * `rc-security`; the enum is closed on purpose, so a build that learns a new permission
 * without the interface learning it fails validation rather than rendering a name
 * nobody has written a control for.
 */
export const permissionSchema = z.enum(['control_input', 'transfer_files', 'view_metrics']);
export type Permission = z.infer<typeof permissionSchema>;

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
    /**
     * What the other machine granted this session.
     *
     * Rides on the state so it arrives with the session and vanishes with it: there is
     * no separate call that could report a grant for a connection that has ended.
     */
    permissions: z.array(permissionSchema),
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

/** Disconnect deliberately. Suppresses automatic reconnection. */
export function disconnectFromServer(): Promise<ConnectionState> {
  return call('disconnect_from_server', connectionStateSchema);
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

/* -------------------------------------------------------------------------- */
/* The host side: accepting connections on this machine                       */
/* -------------------------------------------------------------------------- */

/**
 * A machine name chosen by whoever owns that machine.
 *
 * Stripped first and measured second: a name made entirely of control characters or
 * bidi overrides renders as nothing at all, and a length check applied before the strip
 * would let it through.
 */
const machineName = untrustedText(64).refine(
  (value) => value.length > 0,
  'a machine name is required',
);

/** Whether this machine is accepting connections, and where it can be reached. */
export const hostStatusSchema = z.object({
  accepting: z.boolean(),
  /** Every address a peer could dial to reach this machine, `host:port`. */
  addresses: z.array(z.string().min(1)),
  machineName,
  listenPort: z.number().int().min(1).max(65535),
});

export type HostStatus = z.infer<typeof hostStatusSchema>;

/**
 * An incoming connection waiting for a human to decide.
 *
 * `machineName` is chosen by the peer, so it goes through `untrustedText` — the same
 * treatment remote file names get, and for the same reason. The fingerprint does not:
 * it is generated locally from the observed certificate and must reach the interface
 * byte-for-byte, since comparing it is the whole point of showing it.
 */
export const acceptRequestSchema = z.object({
  requestId: z.string().min(1),
  address: z.string().min(1),
  fingerprint: fingerprintSchema,
  machineName: untrustedText(64),
});

export type AcceptRequest = z.infer<typeof acceptRequestSchema>;

/** A machine this installation has connected to before. */
export const recentSchema = z.object({
  address: z.string().min(1),
  machineName: untrustedText(64),
  lastConnectedMs: z.number().int(),
  /** Whether a pinned identity lets this machine in without asking. */
  alwaysAllow: z.boolean(),
  /** What an always-allow connection receives. Empty unless `alwaysAllow`. */
  pinnedPermissions: z.array(permissionSchema),
});

export type Recent = z.infer<typeof recentSchema>;

/**
 * This machine's own settings.
 *
 * Note what is absent. There is no field for the unattended password or its hash, and
 * the schema strips unknown keys rather than passing them through, so a backend that
 * started sending one would not deliver it to the webview.
 */
export const settingsSchema = z.object({
  accepting: z.boolean(),
  listenPort: z.number().int().min(1).max(65535),
  machineName,
  /** Whether a password is set. Never the password, and never its hash. */
  unattendedConfigured: z.boolean(),
  /** What an unattended-password connection receives. Empty unless configured. */
  unattendedPermissions: z.array(permissionSchema),
});

export type Settings = z.infer<typeof settingsSchema>;

/** Whether this machine is accepting, and where it can be reached. */
export function getHostStatus(): Promise<HostStatus> {
  return call('host_status', hostStatusSchema);
}

/** Start or stop accepting incoming connections. */
export function setAccepting(accepting: boolean): Promise<HostStatus> {
  return call('set_accepting', hostStatusSchema, { accepting });
}

/** The connection waiting on a decision, if one is waiting. */
export function getPendingAcceptRequest(): Promise<AcceptRequest | null> {
  return call('pending_accept_request', acceptRequestSchema.nullable());
}

/**
 * Answer a pending request.
 *
 * An empty `granted` is a refusal, not an empty session — the backend treats it as one,
 * in one place, rather than the interface deciding separately.
 */
export function answerAcceptRequest(requestId: string, granted: Permission[]): Promise<null> {
  return call('answer_accept_request', z.null(), { requestId, granted });
}

/**
 * Subscribe to accept requests raised by the backend.
 *
 * Two callbacks rather than one: a request appearing and a request being withdrawn are
 * different events, and a dialog that only learned about the first would sit on screen
 * after its request had already timed out, inviting a click that lands on nothing.
 *
 * A payload that does not parse is dropped rather than shown. The machine name in it is
 * chosen by whoever is knocking, and a malformed request is not one to render.
 */
export async function listenAcceptRequests(
  onRaised: (request: AcceptRequest) => void,
  onWithdrawn: () => void,
): Promise<() => void> {
  const { listen } = await import('@tauri-apps/api/event');

  const stopRaised = await listen('rc://accept-request', (event) => {
    const parsed = acceptRequestSchema.safeParse(event.payload);
    if (parsed.success) onRaised(parsed.data);
  });
  const stopWithdrawn = await listen('rc://accept-resolved', () => {
    onWithdrawn();
  });

  return () => {
    stopRaised();
    stopWithdrawn();
  };
}

/**
 * Refuse a pending request.
 *
 * A separate call from answering with nothing, so "No" is an explicit act rather than
 * an accept that happens to carry no permissions.
 */
export function dismissAcceptRequest(requestId: string): Promise<null> {
  return call('dismiss_accept_request', z.null(), { requestId });
}

/**
 * Connect to a machine by address.
 *
 * `address` must be the canonical form from `parseAddress`: it is the key the other
 * machine pins on, so a different spelling of the same address is a different machine
 * as far as its "always allow" list is concerned.
 */
export function connectToAddress(
  address: string,
  unattendedPassword: string | null,
): Promise<ConnectionState> {
  return call('connect_to_address', connectionStateSchema, { address, unattendedPassword });
}

/** Machines connected to before, most recent first. */
export function listRecent(): Promise<Recent[]> {
  return call('list_recent', z.array(recentSchema));
}

/**
 * Pin or unpin a machine's identity.
 *
 * Pinning requires an identity to pin, which only a connection can supply, so turning
 * this on for an address this installation has not seen connect is an error rather than
 * a pin of nothing.
 */
export function setAlwaysAllow(address: string, always: boolean): Promise<null> {
  return call('set_always_allow', z.null(), { address, always });
}

/** Forget a machine, pin included. */
export function removeRecent(address: string): Promise<null> {
  return call('remove_recent', z.null(), { address });
}

/** This machine's settings. */
export function getHostSettings(): Promise<Settings> {
  return call('host_settings', settingsSchema);
}

/**
 * Set or clear the unattended-access password.
 *
 * Passing `null` clears it, and clearing it also clears what it granted — the backend
 * writes both together so a password can never be removed while leaving permissions
 * behind for the next one.
 */
export function setUnattendedPassword(
  password: string | null,
  permissions: Permission[],
): Promise<null> {
  return call('set_unattended_password', z.null(), { password, permissions });
}
