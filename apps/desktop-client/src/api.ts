/**
 * Typed wrappers around the backend commands the client exposes.
 *
 * Each wrapper pairs a command name with the schema its response must satisfy. As
 * features land in later phases, they are added here rather than calling `invoke`
 * directly from a component.
 */

import { protocolVersionSchema } from '@rc/shared-types';
import { z } from 'zod';

import { call } from './ipc.js';

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
