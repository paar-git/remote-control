import { describe, expect, it } from 'vitest';

import {
  type SavedDevice,
  compareDevices,
  connectionCandidates,
  devicePreferencesSchema,
  isConnectable,
  macAddressSchema,
  savedDeviceSchema,
} from './devices.js';

const RAW_DEVICE = {
  deviceId: 'dev_1f0c9a2b-3d4e-4f5a-8b6c-7d8e9f0a1b2c',
  displayName: 'home-server',
  hostname: 'server.local',
  osFamily: 'linux',
  osVersion: 'Ubuntu 24.04',
  certificateFingerprint: 'a'.repeat(64),
  pairedAtMs: 1_700_000_000_000,
  lastConnectedAtMs: null,
  lastKnownEndpoint: null,
  remoteEndpoint: null,
  wakeOnLanMac: null,
  favorite: false,
  revoked: false,
  preferences: {},
} as const;

const device = (overrides: Record<string, unknown> = {}): SavedDevice =>
  savedDeviceSchema.parse({ ...RAW_DEVICE, ...overrides });

describe('saved device schema', () => {
  it('parses a minimal device and fills in preference defaults', () => {
    const parsed = device();
    expect(parsed.preferences.autoReconnect).toBe(true);
    expect(parsed.preferences.quality).toBe('adaptive');
    expect(parsed.preferences.fallbackEndpoints).toEqual([]);
  });

  it('rejects a device with a malformed fingerprint', () => {
    expect(
      savedDeviceSchema.safeParse({ ...RAW_DEVICE, certificateFingerprint: 'x' }).success,
    ).toBe(false);
  });

  it('sanitises hostile display names', () => {
    const parsed = device({ displayName: 'serv‮exe.txt' });
    expect(parsed.displayName).not.toContain('‮');
  });

  it('rejects an out-of-range port in an endpoint', () => {
    for (const port of [0, 65_536, -1, 1.5]) {
      expect(
        savedDeviceSchema.safeParse({
          ...RAW_DEVICE,
          lastKnownEndpoint: { host: 'server.local', port },
        }).success,
        String(port),
      ).toBe(false);
    }
  });

  it('caps the number of fallback endpoints', () => {
    const tooMany = Array.from({ length: 9 }, (_, i) => ({ host: 'h', port: 1000 + i }));
    expect(devicePreferencesSchema.safeParse({ fallbackEndpoints: tooMany }).success).toBe(false);
  });
});

describe('MAC addresses', () => {
  it('normalises separators and case', () => {
    expect(macAddressSchema.parse('AA-BB-CC-DD-EE-FF')).toBe('aa:bb:cc:dd:ee:ff');
    expect(macAddressSchema.parse('aa:bb:cc:dd:ee:ff')).toBe('aa:bb:cc:dd:ee:ff');
  });

  it('rejects malformed addresses', () => {
    for (const value of ['aa:bb:cc:dd:ee', 'zz:bb:cc:dd:ee:ff', '', 'aabbccddeeff']) {
      expect(macAddressSchema.safeParse(value).success, value).toBe(false);
    }
  });
});

describe('connectability', () => {
  it('allows connecting to a normal device', () => {
    expect(isConnectable(device())).toBe(true);
  });

  it('refuses to connect to a revoked device', () => {
    expect(isConnectable(device({ revoked: true }))).toBe(false);
  });
});

describe('connection candidates', () => {
  it('tries the last known address first', () => {
    const candidates = connectionCandidates(
      device({
        lastKnownEndpoint: { host: '192.168.1.50', port: 47811 },
        remoteEndpoint: { host: 'vpn.example.com', port: 47811 },
        preferences: { fallbackEndpoints: [{ host: '192.168.1.51', port: 47811 }] },
      }),
    );
    expect(candidates.map((c) => c.host)).toEqual([
      '192.168.1.50',
      '192.168.1.51',
      'vpn.example.com',
    ]);
  });

  it('deduplicates repeated endpoints', () => {
    const same = { host: '192.168.1.50', port: 47811 };
    const candidates = connectionCandidates(
      device({
        lastKnownEndpoint: same,
        remoteEndpoint: same,
        preferences: { fallbackEndpoints: [same] },
      }),
    );
    expect(candidates).toHaveLength(1);
  });

  it('returns an empty list for a device with no known endpoints', () => {
    // Not an error: discovery is expected to supply one.
    expect(connectionCandidates(device())).toEqual([]);
  });

  it('treats the same host on different ports as distinct', () => {
    const candidates = connectionCandidates(
      device({
        lastKnownEndpoint: { host: 'server', port: 47811 },
        preferences: { fallbackEndpoints: [{ host: 'server', port: 47812 }] },
      }),
    );
    expect(candidates).toHaveLength(2);
  });
});

describe('device ordering', () => {
  it('puts favorites first', () => {
    const list = [device({ displayName: 'b' }), device({ displayName: 'a', favorite: true })];
    list.sort(compareDevices);
    expect(list[0]?.displayName).toBe('a');
  });

  it('orders by most recently connected within a group', () => {
    const list = [
      device({ displayName: 'old', lastConnectedAtMs: 1000 }),
      device({ displayName: 'new', lastConnectedAtMs: 2000 }),
      device({ displayName: 'never', lastConnectedAtMs: null }),
    ];
    list.sort(compareDevices);
    expect(list.map((d) => d.displayName)).toEqual(['new', 'old', 'never']);
  });

  it('falls back to name order', () => {
    const list = [device({ displayName: 'zeta' }), device({ displayName: 'alpha' })];
    list.sort(compareDevices);
    expect(list.map((d) => d.displayName)).toEqual(['alpha', 'zeta']);
  });
});
