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
 * This validates format only. It proves nothing about correctness — completing a
 * pairing requires the network transport, which arrives in phase 3.
 */
export function checkPairingCodeFormat(code: string): Promise<boolean> {
  return call('check_pairing_code_format', z.boolean(), { code });
}
