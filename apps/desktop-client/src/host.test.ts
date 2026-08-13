import { describe, expect, it } from 'vitest';

import { acceptRequestSchema, hostStatusSchema, recentSchema, settingsSchema } from './api.js';

describe('host DTO schemas', () => {
  it('accepts a well-formed host status', () => {
    const parsed = hostStatusSchema.parse({
      accepting: true,
      addresses: ['192.168.1.42:7443'],
      machineName: 'KOREN-PC',
      listenPort: 7443,
    });
    expect(parsed.addresses).toHaveLength(1);
  });

  it('refuses a host status with no machine name', () => {
    expect(() =>
      hostStatusSchema.parse({ accepting: true, addresses: [], machineName: '', listenPort: 7443 }),
    ).toThrow();
  });

  it('refuses a machine name that is only control characters', () => {
    // The name is stripped before it is measured, so a name that renders as nothing
    // is caught rather than passing a length check on characters that never display.
    expect(() =>
      hostStatusSchema.parse({
        accepting: true,
        addresses: [],
        machineName: '‮',
        listenPort: 7443,
      }),
    ).toThrow();
  });

  it('accepts an accept request and keeps the fingerprint intact', () => {
    const parsed = acceptRequestSchema.parse({
      requestId: 'r1',
      address: '192.168.1.77:7443',
      fingerprint: 'a'.repeat(64),
      machineName: 'WORK-LAPTOP',
    });
    expect(parsed.fingerprint).toHaveLength(64);
  });

  it('strips control characters and bidi overrides from an untrusted machine name', () => {
    // The peer chooses this string. Without stripping, a name can be made to render
    // as a different one.
    const parsed = acceptRequestSchema.parse({
      requestId: 'r1',
      address: '192.168.1.77:7443',
      fingerprint: 'a'.repeat(64),
      machineName: 'WORK‮POTAL',
    });
    expect(parsed.machineName).toBe('WORKPOTAL');
  });

  it('refuses a recent entry whose pinned permissions are unknown', () => {
    expect(() =>
      recentSchema.parse({
        address: '192.168.1.77:7443',
        machineName: 'WORK-LAPTOP',
        lastConnectedMs: 1,
        alwaysAllow: true,
        pinnedPermissions: ['control_input', 'launch_missiles'],
      }),
    ).toThrow();
  });

  it('accepts a recent entry with no pin', () => {
    const parsed = recentSchema.parse({
      address: '192.168.1.77:7443',
      machineName: 'WORK-LAPTOP',
      lastConnectedMs: 1,
      alwaysAllow: false,
      pinnedPermissions: [],
    });
    expect(parsed.alwaysAllow).toBe(false);
    expect(parsed.pinnedPermissions).toEqual([]);
  });

  it('refuses settings carrying anything password-shaped', () => {
    // The hash must never cross the IPC boundary. A backend that started sending one
    // should fail here rather than have it reach the webview unnoticed.
    const parsed = settingsSchema.parse({
      accepting: true,
      listenPort: 7443,
      machineName: 'KOREN-PC',
      unattendedConfigured: true,
      unattendedPermissions: ['view_metrics'],
      unattendedPhc: '$argon2id$v=19$m=19456,t=2,p=1$abc$def',
    });
    expect(parsed).not.toHaveProperty('unattendedPhc');
  });
});
