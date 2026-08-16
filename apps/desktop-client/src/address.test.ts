import { describe, expect, it } from 'vitest';

import { parseAddress } from './address.js';

describe('parseAddress', () => {
  it('accepts a bare IPv4 address and applies the default port', () => {
    expect(parseAddress('192.168.1.77')).toEqual({ ok: true, value: '192.168.1.77:7443' });
  });

  it('accepts an explicit port', () => {
    expect(parseAddress('192.168.1.77:9000')).toEqual({ ok: true, value: '192.168.1.77:9000' });
  });

  it('accepts a bracketed IPv6 address', () => {
    expect(parseAddress('[fe80::1]:9000')).toEqual({ ok: true, value: '[fe80::1]:9000' });
  });

  it('accepts a hostname', () => {
    expect(parseAddress('work-laptop.local')).toEqual({
      ok: true,
      value: 'work-laptop.local:7443',
    });
  });

  it('trims surrounding whitespace', () => {
    expect(parseAddress('  192.168.1.77  ')).toEqual({ ok: true, value: '192.168.1.77:7443' });
  });

  it('reports an empty address rather than silently doing nothing', () => {
    const result = parseAddress('');
    expect(result.ok).toBe(false);
  });

  it('refuses a URL', () => {
    expect(parseAddress('https://192.168.1.77').ok).toBe(false);
  });

  it('refuses port zero', () => {
    expect(parseAddress('192.168.1.77:0').ok).toBe(false);
  });

  it('refuses a port above the range', () => {
    expect(parseAddress('192.168.1.77:70000').ok).toBe(false);
  });

  it('gives a reason a person can act on', () => {
    const result = parseAddress('https://192.168.1.77');
    if (result.ok) throw new Error('expected a refusal');
    expect(result.reason).toMatch(/address/i);
    expect(result.reason).not.toMatch(/undefined|error|null/i);
  });

  /*
   * The cases below are not in the plan. They are the ones where this parser could
   * disagree with `PeerAddress::from_str`, which is the only way a second
   * implementation can do harm: the backend re-validates everything, so this one being
   * stricter means refusing an address that would have worked.
   */

  it('takes an unbracketed IPv6 address whole rather than guessing at a port', () => {
    // `fe80::1:9000` is genuinely ambiguous — indistinguishable from an address whose
    // last group is 9000. The Rust parser takes the whole string as the host and
    // applies the default port; brackets are how the user says otherwise.
    // Rendering it back adds the brackets that were missing, so the port is
    // unambiguous next time. Cross-checked against the Rust parser in
    // crates/transport/tests/address_cross_check.rs.
    expect(parseAddress('fe80::1:9000')).toEqual({ ok: true, value: '[fe80::1:9000]:7443' });
  });

  it('refuses a bracketed address that is not IPv6', () => {
    // `[192.168.1.77]` parses as brackets around something that is not an IPv6
    // address. The Rust parser requires the contents to be genuinely V6.
    expect(parseAddress('[192.168.1.77]:9000').ok).toBe(false);
  });

  it('refuses an unclosed bracket', () => {
    expect(parseAddress('[fe80::1:9000').ok).toBe(false);
  });

  it('refuses an address longer than the column that stores it', () => {
    // 255 characters, matching the CHECK on `recent_connections.address`. A longer one
    // would be accepted here and rejected on save.
    expect(parseAddress(`${'a'.repeat(249)}.local`).ok).toBe(true);
    expect(parseAddress(`${'a'.repeat(250)}.local`).ok).toBe(false);
  });

  it('refuses an empty host with a port', () => {
    expect(parseAddress(':9000').ok).toBe(false);
    expect(parseAddress('[]:9000').ok).toBe(false);
  });

  it('refuses a trailing colon with no port', () => {
    expect(parseAddress('192.168.1.77:').ok).toBe(false);
  });

  it('refuses a port that is not a number', () => {
    expect(parseAddress('192.168.1.77:https').ok).toBe(false);
  });

  it('preserves the host as typed rather than lowercasing it', () => {
    // The Rust parser does not normalise case either. If one side normalised and the
    // other did not, the same machine would key two different entries in the recent
    // list.
    expect(parseAddress('WORK-Laptop.local')).toEqual({
      ok: true,
      value: 'WORK-Laptop.local:7443',
    });
  });

  it('refuses a host with a path, a query or a space', () => {
    for (const text of ['192.168.1.77/admin', '192.168.1.77?x=1', 'work laptop']) {
      expect(parseAddress(text).ok, text).toBe(false);
    }
  });
});
