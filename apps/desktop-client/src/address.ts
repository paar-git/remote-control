/**
 * The address a user types to reach another machine.
 *
 * # This is deliberately a second implementation
 *
 * `PeerAddress::from_str` in `crates/transport/src/address.rs` is the authority, and it
 * re-parses everything this file accepts. Nothing here is trusted by the backend and
 * nothing here can widen what the backend admits.
 *
 * It exists so a typo is reported under the field while the user is still looking at
 * it, rather than surfacing seconds later as a connection failure that looks exactly
 * like an unreachable machine. That is a real difference to the person using this, and
 * it is worth one duplicated parser.
 *
 * **Do not "remove the duplication" by deleting either side.** Deleting this one moves
 * every typo to a timeout. Deleting the Rust one would make the interface the only
 * validator of something that arrives over IPC, which is not a boundary a webview gets
 * to be trusted at.
 *
 * The two must agree, and the agreement is tested from both sides. In particular, this
 * parser must never be *stricter* than the Rust one: refusing an address the backend
 * would have accepted is a bug the user cannot work around.
 */

/** The port used when the address does not name one. Mirrors `PeerAddress::DEFAULT_PORT`. */
export const DEFAULT_PORT = 7443;

/** The longest address accepted, matching the database column's `CHECK`. */
const MAX_LENGTH = 255;

/** A parsed address, or the reason it was refused. */
export type ParsedAddress = { ok: true; value: string } | { ok: false; reason: string };

/** Whether `text` is an IPv4 literal, by the same rule `IpAddr` applies. */
function isIpv4(text: string): boolean {
  const parts = text.split('.');
  if (parts.length !== 4) return false;
  return parts.every(
    (part) =>
      /^\d{1,3}$/.test(part) &&
      Number(part) <= 255 &&
      // `01` is not a valid octet: Rust's parser rejects leading zeroes rather than
      // reading them as octal or ignoring them.
      (part === '0' || !part.startsWith('0')),
  );
}

/**
 * Whether `text` is an IPv6 literal.
 *
 * Covers the compressed `::` form and the IPv4-mapped tail, which are the two shapes a
 * person actually types.
 */
function isIpv6(text: string): boolean {
  if (!text.includes(':')) return false;
  if ((text.match(/::/g) ?? []).length > 1) return false;

  let body = text;
  let tailGroups = 0;

  // A trailing IPv4 part, as in `::ffff:192.168.1.77`, stands for two groups.
  const lastColon = body.lastIndexOf(':');
  const tail = body.slice(lastColon + 1);
  if (tail.includes('.')) {
    if (!isIpv4(tail)) return false;
    body = body.slice(0, lastColon + 1);
    tailGroups = 2;
  }

  const compressed = body.includes('::');
  const groups = body
    .split(':')
    .filter((group) => group !== '')
    .map((group) => group);

  if (!groups.every((group) => /^[0-9a-fA-F]{1,4}$/.test(group))) return false;

  const total = groups.length + tailGroups;
  return compressed ? total <= 7 : total === 8;
}

/** Whether `host` could be a hostname or an IP literal. Mirrors `is_plausible_host`. */
function isPlausibleHost(host: string): boolean {
  if (isIpv4(host) || isIpv6(host)) return true;
  return (
    host.length > 0 &&
    !host.startsWith('-') &&
    !host.endsWith('-') &&
    !host.startsWith('.') &&
    !host.endsWith('.') &&
    /^[a-zA-Z0-9.-]+$/.test(host)
  );
}

/** A port a peer could actually be listening on. Zero means "any", so it is never one. */
function parsePort(text: string): number | null {
  if (!/^\d{1,5}$/.test(text)) return null;
  const port = Number(text);
  return port >= 1 && port <= 65535 ? port : null;
}

/**
 * Parse what the user typed into the canonical `host:port` the backend expects.
 *
 * The refusal reasons name what is wrong with the address rather than what the parser
 * did, because the person reading them is trying to fix their typing.
 */
export function parseAddress(text: string): ParsedAddress {
  const trimmed = text.trim();
  const refuse = (reason: string): ParsedAddress => ({ ok: false, reason });

  if (trimmed.length === 0) {
    return refuse('Enter the address of the machine to connect to.');
  }
  if (trimmed.length > MAX_LENGTH) {
    return refuse(`That address is too long. Use at most ${MAX_LENGTH} characters.`);
  }
  // A scheme, a path or a query means a URL was typed. Half-understanding it would
  // imply the connection honours the scheme, and it does not — this is always QUIC.
  if (trimmed.includes('://') || trimmed.includes('/') || trimmed.includes('?')) {
    return refuse('Enter an address like 192.168.1.77 — not a web address.');
  }

  let host: string;
  let port: number;

  if (trimmed.startsWith('[')) {
    // Bracketed: an IPv6 literal, with or without a port.
    const close = trimmed.indexOf(']');
    if (close === -1) {
      return refuse('That address is missing its closing bracket.');
    }
    const inside = trimmed.slice(1, close);
    const after = trimmed.slice(close + 1);

    if (after === '') {
      port = DEFAULT_PORT;
    } else if (after.startsWith(':')) {
      const parsed = parsePort(after.slice(1));
      if (parsed === null) {
        return refuse('That port is not a number between 1 and 65535.');
      }
      port = parsed;
    } else {
      return refuse('That address is not one this application can use.');
    }

    // Brackets mean IPv6 specifically. A bracketed IPv4 address or hostname is a
    // malformed address, not a generous synonym.
    if (!isIpv6(inside)) {
      return refuse('Square brackets are only for IPv6 addresses.');
    }
    host = inside;
  } else if ((trimmed.match(/:/g) ?? []).length > 1) {
    // More than one colon and no brackets: an unbracketed IPv6 address. The whole
    // string is the host — a trailing group cannot be told from a port. Brackets are
    // how the user says otherwise.
    if (!isIpv6(trimmed)) {
      return refuse('That address is not one this application can use.');
    }
    host = trimmed;
    port = DEFAULT_PORT;
  } else if (trimmed.includes(':')) {
    const at = trimmed.indexOf(':');
    host = trimmed.slice(0, at);
    const parsed = parsePort(trimmed.slice(at + 1));
    if (parsed === null) {
      return refuse('That port is not a number between 1 and 65535.');
    }
    port = parsed;
  } else {
    host = trimmed;
    port = DEFAULT_PORT;
  }

  if (!isPlausibleHost(host)) {
    return refuse('That address is not one this application can use.');
  }

  // Matches `Display for PeerAddress`: a host containing a colon is IPv6 and is
  // bracketed, so the port is unambiguous.
  return { ok: true, value: host.includes(':') ? `[${host}]:${port}` : `${host}:${port}` };
}

/**
 * Format an address for display, hiding the port when it is the default one.
 *
 * The port is noise in the common case and load-bearing in the rare one, so it is shown
 * only when it is not what everyone else uses.
 */
export function displayAddress(canonical: string): string {
  const suffix = `:${DEFAULT_PORT}`;
  return canonical.endsWith(suffix) ? canonical.slice(0, -suffix.length) : canonical;
}
