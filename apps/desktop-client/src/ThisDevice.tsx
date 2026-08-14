/**
 * This machine: name, readiness, the permanent device ID, and the incoming switch.
 *
 * IPv4, IPv6 and hostname sit behind a disclosure. Nobody should need to understand
 * IPv6 to use this.
 */

import { Share2 } from 'lucide-react';
import { useState } from 'react';

import type { HostStatus, LocalIdentity } from './api.js';
import { DeviceAvatar } from './DeviceAvatar';
import { formatDeviceId } from './format.js';
import { Button, CopyButton, StatusBadge, Toggle } from './ui';

export function ThisDevice({
  status,
  identity,
  os,
  hostname,
  onToggleAccepting,
  toggling = false,
}: {
  readonly status: HostStatus;
  readonly identity: LocalIdentity | null;
  readonly os?: 'windows' | 'linux' | 'macos' | 'unknown' | undefined;
  readonly hostname?: string | undefined;
  readonly onToggleAccepting: (next: boolean) => void;
  readonly toggling?: boolean | undefined;
}): React.JSX.Element {
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [shared, setShared] = useState(false);
  const primary = primaryAddress(status.addresses);
  const ipv6 = status.addresses.filter(isIpv6);
  const deviceId = identity === null ? '—' : formatDeviceId(identity.identityFingerprint);

  const share = (): void => {
    const lines = [
      status.machineName,
      `Device ID: ${deviceId}`,
      ...(primary === null ? [] : [`Address: ${primary}`]),
    ];
    void navigator.clipboard.writeText(lines.join('\n')).then(() => {
      setShared(true);
      window.setTimeout(() => {
        setShared(false);
      }, 2000);
    });
  };

  return (
    <section className="rounded-[var(--radius-card)] border border-(--color-border) bg-(--color-card) p-6 shadow-(--shadow-card)">
      <h2 className="mb-5 text-xl font-semibold tracking-tight">This Device</h2>

      <div className="flex flex-col gap-5">
        <div className="flex items-start gap-3">
          <DeviceAvatar name={status.machineName} os={os} />
          <div className="min-w-0">
            <p className="truncate text-lg font-semibold" title={status.machineName}>
              {status.machineName}
            </p>
            <p role="status" className="mt-1">
              <StatusBadge tone={status.accepting ? 'ready' : 'idle'}>
                {status.accepting ? 'Ready for connections' : 'Not accepting connections'}
              </StatusBadge>
            </p>
          </div>
        </div>

        <div>
          <p className="mb-1 text-sm text-(--color-text-secondary)">Device ID</p>
          <p aria-label="Device ID" className="font-mono text-2xl tracking-wide">
            {deviceId}
          </p>
          <p className="mt-1 text-xs text-(--color-text-secondary)">
            Identity — verify this on the other machine
          </p>
          <div className="mt-2 flex flex-wrap gap-2">
            <CopyButton value={deviceId} label="device ID" size="sm" />
            <Button variant="default" size="sm" icon={Share2} onClick={share}>
              {shared ? 'Copied' : 'Share'}
            </Button>
          </div>
        </div>

        <div>
          <p className="mb-1 text-sm text-(--color-text-secondary)">Connect using</p>
          <div className="flex flex-wrap items-center gap-2">
            <p aria-label="Connect using" className="font-mono text-base tracking-tight">
              {primary ?? '—'}
            </p>
            {primary !== null && <CopyButton value={primary} label="address" size="sm" />}
          </div>
        </div>

        <div className="flex items-center justify-between gap-3">
          <div>
            <p className="text-sm font-medium">Allow incoming connections</p>
            <p className="text-xs text-(--color-text-secondary)">
              Other machines can reach this one only while this is on.
            </p>
          </div>
          <Toggle
            label="Allow incoming connections"
            checked={status.accepting}
            disabled={toggling}
            onChange={onToggleAccepting}
          />
        </div>

        <div>
          <button
            type="button"
            className="text-sm font-medium text-(--color-text-secondary) hover:text-(--color-text)"
            aria-expanded={advancedOpen}
            onClick={() => {
              setAdvancedOpen((open) => !open);
            }}
          >
            Advanced network information
          </button>
          {advancedOpen && (
            <dl className="mt-3 flex flex-col gap-2 text-sm">
              <InfoRow label="IPv4" value={ipv4Of(status.addresses) ?? '—'} />
              {ipv6.map((address) => (
                <InfoRow key={address} label="IPv6" value={displayIpv6(address)} />
              ))}
              <InfoRow label="Hostname" value={hostname ?? '—'} />
              <InfoRow label="Listen port" value={String(status.listenPort)} />
              <InfoRow label="Connection method" value="Direct QUIC / TLS 1.3" />
              <InfoRow
                label="Local network"
                value={
                  status.accepting
                    ? `Listening on ${String(status.listenPort)}`
                    : 'Not accepting connections'
                }
              />
              <InfoRow label="Relay" value="Not used — this build connects directly" />
            </dl>
          )}
        </div>
      </div>
    </section>
  );
}

function InfoRow({ label, value }: { readonly label: string; readonly value: string }) {
  return (
    <div className="flex gap-3">
      <dt className="w-36 shrink-0 text-(--color-text-secondary)">{label}</dt>
      <dd className="min-w-0 flex-1 font-mono text-xs break-all">{value}</dd>
    </div>
  );
}

function isIpv6(address: string): boolean {
  return address.startsWith('[');
}

function displayIpv6(address: string): string {
  const close = address.indexOf(']');
  return close === -1 ? address : address.slice(1, close);
}

function ipv4Of(addresses: readonly string[]): string | undefined {
  return addresses.find((address) => !isIpv6(address));
}

function primaryAddress(addresses: readonly string[]): string | null {
  return ipv4Of(addresses) ?? addresses[0] ?? null;
}
