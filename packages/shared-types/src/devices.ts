/**
 * Saved-device schemas. These describe what the client persists about a server so it
 * can be reconnected to without re-entering anything.
 */

import { z } from 'zod';

import { deviceIdSchema, fingerprintSchema, timestampMs, untrustedText } from './primitives.js';

/** Operating-system family, mirroring the Rust `OsFamily`. */
export const osFamilySchema = z.enum(['windows', 'linux', 'macos', 'unknown']);
export type OsFamily = z.infer<typeof osFamilySchema>;

/**
 * A MAC address for Wake-on-LAN, in colon or hyphen separated hex.
 * Normalised to lowercase colon-separated form.
 */
export const macAddressSchema = z
  .string()
  .regex(/^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i, 'must be a MAC address')
  .transform((value) => value.toLowerCase().replaceAll('-', ':'));

/** A network endpoint the client may try when connecting. */
export const endpointSchema = z.object({
  host: z.string().min(1).max(253),
  port: z.number().int().min(1).max(65535),
});

export type Endpoint = z.infer<typeof endpointSchema>;

/** Per-device connection preferences. */
export const devicePreferencesSchema = z.object({
  /** Reconnect automatically after an unexpected drop. */
  autoReconnect: z.boolean().default(true),
  /** Synchronise the clipboard between the two machines. */
  clipboardSync: z.boolean().default(true),
  /** Start remote-desktop sessions in view-only mode. */
  startViewOnly: z.boolean().default(false),
  /** Preferred display index to capture. */
  preferredMonitor: z.number().int().min(0).max(255).default(0),
  /** Video quality preset. */
  quality: z.enum(['low', 'balanced', 'high', 'lossless', 'adaptive']).default('adaptive'),
  /** Extra endpoints to try when the last known address fails. */
  fallbackEndpoints: z.array(endpointSchema).max(8).default([]),
});

export type DevicePreferences = z.infer<typeof devicePreferencesSchema>;

/**
 * A device saved in the client's device list.
 *
 * `displayName`, `hostname` and `osVersion` come from the remote host and are
 * therefore sanitised on the way in.
 */
export const savedDeviceSchema = z.object({
  deviceId: deviceIdSchema,
  displayName: untrustedText(128),
  hostname: untrustedText(253),
  osFamily: osFamilySchema,
  osVersion: untrustedText(128),
  /** Pinned identity. A change here is a hard, user-visible failure. */
  certificateFingerprint: fingerprintSchema,
  pairedAtMs: timestampMs,
  lastConnectedAtMs: timestampMs.nullable(),
  lastKnownEndpoint: endpointSchema.nullable(),
  remoteEndpoint: endpointSchema.nullable(),
  wakeOnLanMac: macAddressSchema.nullable(),
  favorite: z.boolean(),
  /** Trust was withdrawn. Retained for the audit trail; cannot be connected to. */
  revoked: z.boolean(),
  preferences: devicePreferencesSchema,
});

export type SavedDevice = z.infer<typeof savedDeviceSchema>;

/** Live reachability of a saved device, tracked separately from persisted data. */
export const devicePresenceSchema = z.enum(['online', 'offline', 'unknown']);
export type DevicePresence = z.infer<typeof devicePresenceSchema>;

/** Whether a saved device can currently be connected to. */
export function isConnectable(device: SavedDevice): boolean {
  return !device.revoked;
}

/**
 * Endpoints to try, in the order the Reconnect button should try them.
 *
 * The last known good address comes first because on a home LAN it almost always
 * still works, which is what makes reconnection feel instant. Discovery and the
 * coordination service are handled by the caller around this list.
 */
export function connectionCandidates(device: SavedDevice): Endpoint[] {
  const candidates: Endpoint[] = [];
  const seen = new Set<string>();

  const push = (endpoint: Endpoint | null): void => {
    if (endpoint === null) return;
    const key = `${endpoint.host}:${endpoint.port}`;
    if (seen.has(key)) return;
    seen.add(key);
    candidates.push(endpoint);
  };

  push(device.lastKnownEndpoint);
  for (const endpoint of device.preferences.fallbackEndpoints) push(endpoint);
  push(device.remoteEndpoint);

  return candidates;
}

/** Sort order for the device list: favorites first, then most recently connected. */
export function compareDevices(a: SavedDevice, b: SavedDevice): number {
  if (a.favorite !== b.favorite) return a.favorite ? -1 : 1;
  const aTime = a.lastConnectedAtMs ?? 0;
  const bTime = b.lastConnectedAtMs ?? 0;
  if (aTime !== bTime) return bTime - aTime;
  return a.displayName.localeCompare(b.displayName);
}
