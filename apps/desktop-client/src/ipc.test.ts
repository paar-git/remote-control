import { invoke } from '@tauri-apps/api/core';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

import { clientInfoSchema, getClientInfo } from './api.js';
import { IpcError, IpcValidationError, call } from './ipc.js';

const mockInvoke = vi.mocked(invoke);

const VALID_INFO = {
  appVersion: '0.1.0',
  protocolVersion: { major: 1, minor: 0 },
  hostname: 'main-pc',
  osFamily: 'windows',
  osVersion: 'Windows 11 Pro',
  architecture: 'x86_64',
  elevated: false,
  databaseReady: true,
};

beforeEach(() => {
  mockInvoke.mockReset();
});

describe('call', () => {
  const schema = z.object({ value: z.number() });

  it('returns the parsed response', async () => {
    mockInvoke.mockResolvedValue({ value: 42 });
    await expect(call('demo', schema)).resolves.toEqual({ value: 42 });
  });

  it('forwards arguments to the backend', async () => {
    mockInvoke.mockResolvedValue({ value: 1 });
    await call('demo', schema, { deviceId: 'dev_x' });
    expect(mockInvoke).toHaveBeenCalledWith('demo', { deviceId: 'dev_x' });
  });

  it('wraps a backend failure in an IpcError naming the command', async () => {
    mockInvoke.mockRejectedValue(new Error('database is locked'));
    await expect(call('demo', schema)).rejects.toBeInstanceOf(IpcError);
    await expect(call('demo', schema)).rejects.toMatchObject({ command: 'demo' });
  });

  it('handles a non-Error rejection without losing the message', async () => {
    mockInvoke.mockRejectedValue('permission denied');
    await expect(call('demo', schema)).rejects.toThrow('permission denied');
  });

  it('reads the message field from a Tauri command-error object', async () => {
    mockInvoke.mockRejectedValue({ code: 'not_authorized', message: 'That machine refused.' });
    await expect(call('demo', schema)).rejects.toThrow('That machine refused.');
    await expect(call('demo', schema)).rejects.not.toThrow(/object Object/);
  });

  it('rejects a response that does not match the schema', async () => {
    mockInvoke.mockResolvedValue({ value: 'not a number' });
    await expect(call('demo', schema)).rejects.toBeInstanceOf(IpcValidationError);
  });

  it('rejects null and undefined responses rather than passing them through', async () => {
    for (const bad of [null, undefined, 'string', 12]) {
      mockInvoke.mockResolvedValue(bad);
      await expect(call('demo', schema)).rejects.toBeInstanceOf(IpcValidationError);
    }
  });

  it('does not let unexpected extra fields reach the caller unvalidated', async () => {
    mockInvoke.mockResolvedValue({ value: 1, injected: '<script>' });
    const result = await call('demo', schema);
    expect(result).toEqual({ value: 1 });
    expect(Object.keys(result)).toEqual(['value']);
  });
});

describe('getClientInfo', () => {
  it('parses a well-formed response', async () => {
    mockInvoke.mockResolvedValue(VALID_INFO);
    const info = await getClientInfo();
    expect(info.hostname).toBe('main-pc');
    expect(info.protocolVersion).toEqual({ major: 1, minor: 0 });
  });

  it('rejects a response missing a required field', async () => {
    const { databaseReady: _omitted, ...incomplete } = VALID_INFO;
    mockInvoke.mockResolvedValue(incomplete);
    await expect(getClientInfo()).rejects.toBeInstanceOf(IpcValidationError);
  });

  it('rejects an unknown OS family rather than rendering it', async () => {
    mockInvoke.mockResolvedValue({ ...VALID_INFO, osFamily: 'solaris' });
    await expect(getClientInfo()).rejects.toBeInstanceOf(IpcValidationError);
  });

  it('accepts the schema it declares', () => {
    expect(clientInfoSchema.safeParse(VALID_INFO).success).toBe(true);
  });
});
