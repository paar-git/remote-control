import { describe, expect, it } from 'vitest';

import { permissionSchema, sessionRecordSchema, trustedDeviceSchema } from './api.js';

describe('permissionSchema', () => {
  it('knows the administrator permission', () => {
    expect(permissionSchema.safeParse('administer').success).toBe(true);
  });

  it('refuses a permission this build has no control for', () => {
    // The enum is closed on purpose: a backend that learns a permission the
    // interface has not learned must fail validation rather than render a name
    // nobody has written a control for.
    expect(permissionSchema.safeParse('launch_missiles').success).toBe(false);
  });
});

describe('trustedDeviceSchema', () => {
  const valid = {
    identityFingerprint: 'a'.repeat(64),
    deviceId: 'dev-00000000-0000-0000-0000-000000000001',
    displayName: 'Gaming PC',
    osFamily: 'windows',
    lastAddress: '192.168.1.77:7443',
    addedMs: 1_700_000_000_000,
    lastConnectedMs: 1_700_000_060_000,
    unattended: true,
    suspended: false,
    permissions: ['view_metrics'],
  };

  it('accepts a well-formed device', () => {
    expect(trustedDeviceSchema.safeParse(valid).success).toBe(true);
  });

  it('strips a field the backend should never be sending', () => {
    // The schema must not pass through anything resembling a credential, in the
    // same way settingsSchema refuses to carry the unattended password.
    const parsed = trustedDeviceSchema.parse({ ...valid, unattendedPassword: 'hunter2' });
    expect(parsed).not.toHaveProperty('unattendedPassword');
  });

  it('refuses a malformed identity rather than rendering it', () => {
    expect(trustedDeviceSchema.safeParse({ ...valid, identityFingerprint: 'nope' }).success).toBe(
      false,
    );
  });

  it('sanitises a display name chosen by the other machine', () => {
    // A name is chosen by whoever owns that machine. A bidi override in it would
    // render as a different name than it is.
    const parsed = trustedDeviceSchema.parse({ ...valid, displayName: 'co\u202Egnp.exe' });
    expect(parsed.displayName).not.toContain('\u202E');
  });
});

describe('sessionRecordSchema', () => {
  it('accepts a refused connection with no identity and no session', () => {
    const parsed = sessionRecordSchema.safeParse({
      id: 1,
      sessionId: null,
      identityFingerprint: null,
      deviceName: 'Unknown',
      direction: 'incoming',
      address: '10.0.0.9:7443',
      startedMs: 1_700_000_000_000,
      endedMs: null,
      permissions: [],
      outcome: 'refused',
      endReason: null,
    });
    expect(parsed.success).toBe(true);
  });
});
