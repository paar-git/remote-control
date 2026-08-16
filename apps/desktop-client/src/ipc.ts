/**
 * The Tauri IPC boundary.
 *
 * Every value returned by a Rust command is parsed through a Zod schema before it is
 * used. `invoke` returns `unknown` here on purpose: there is no path in this codebase
 * where a backend response is type-asserted into shape.
 */

import { invoke as tauriInvoke } from '@tauri-apps/api/core';
import type { z } from 'zod';

/** A failure crossing the IPC boundary. */
export class IpcError extends Error {
  constructor(
    /** The command that failed. */
    readonly command: string,
    message: string,
    override readonly cause?: unknown,
  ) {
    super(message);
    this.name = 'IpcError';
  }
}

/** Raised when the backend returned something that does not match its schema. */
export class IpcValidationError extends IpcError {
  constructor(command: string, issues: string) {
    super(command, `Response from \`${command}\` did not match its schema: ${issues}`);
    this.name = 'IpcValidationError';
  }
}

/**
 * Call a Rust command and validate its response.
 *
 * @param command - Name of the `#[tauri::command]` to call.
 * @param schema - Schema the response must satisfy.
 * @param args - Arguments passed to the command.
 * @throws {IpcError} if the command itself failed.
 * @throws {IpcValidationError} if the response did not match `schema`.
 */
export async function call<Schema extends z.ZodType>(
  command: string,
  schema: Schema,
  args?: Record<string, unknown>,
): Promise<z.infer<Schema>> {
  let raw: unknown;
  try {
    raw = await tauriInvoke(command, args);
  } catch (cause) {
    throw new IpcError(command, messageFromIpc(cause), cause);
  }

  const parsed = schema.safeParse(raw);
  if (!parsed.success) {
    throw new IpcValidationError(command, parsed.error.issues.map((i) => i.message).join('; '));
  }
  return parsed.data;
}

/** Pull a human sentence out of whatever Tauri rejected with. */
function messageFromIpc(cause: unknown): string {
  if (cause instanceof Error) return cause.message;
  if (typeof cause === 'string' && cause !== '') return cause;
  if (cause !== null && typeof cause === 'object' && 'message' in cause) {
    const message = (cause as { readonly message: unknown }).message;
    if (typeof message === 'string' && message !== '') return message;
  }
  return 'The backend rejected the command.';
}

/** Whether the app is running inside Tauri rather than a plain browser. */
export function isTauriAvailable(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}
