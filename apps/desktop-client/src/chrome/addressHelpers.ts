export function isIpv6(address: string): boolean {
  return address.startsWith('[');
}

export function primaryAddress(addresses: readonly string[]): string | null {
  return addresses.find((address) => !isIpv6(address)) ?? addresses[0] ?? null;
}

export function displayIpv6(address: string): string {
  const close = address.indexOf(']');
  return close === -1 ? address : address.slice(1, close);
}

export function displayIpv4(addresses: readonly string[]): string {
  const found = addresses.find((address) => !isIpv6(address));
  return found ?? '—';
}
