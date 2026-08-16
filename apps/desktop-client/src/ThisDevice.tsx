/**
 * This machine: readiness, name, and a dense settings table.
 */

import { Check, ChevronRight, Copy, ShieldCheck } from 'lucide-react';
import { useState } from 'react';

import { displayAddress } from './address.js';
import type { HostStatus, LocalIdentity } from './api.js';
import { displayIpv4, displayIpv6, isIpv6, Panel, PanelHeader, primaryAddress } from './chrome';
import { DeviceAvatar } from './DeviceAvatar';
import { formatDeviceId } from './format.js';
import { Toggle } from './ui';

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
  const primary = primaryAddress(status.addresses);
  const ipv6 = status.addresses.filter(isIpv6);
  const deviceId = identity === null ? '—' : formatDeviceId(identity.identityFingerprint);

  return (
    <Panel>
      <PanelHeader
        title="This Device"
        trailing={
          <div className="flex items-center gap-3">
            <span className="text-[13px] text-(--color-text-secondary)">Accept connections</span>
            <Toggle
              label="Accept connections"
              checked={status.accepting}
              disabled={toggling}
              onChange={onToggleAccepting}
            />
          </div>
        }
      />

      <div className="flex items-center gap-3 px-[22px] pb-4">
        <DeviceAvatar name={status.machineName} os={os} size="sm" />
        <div className="min-w-0">
          <p className="truncate text-[15px] font-medium" title={status.machineName}>
            {status.machineName}
          </p>
          <p
            role="status"
            className="mt-0.5 flex items-center gap-1.5 text-[13px] text-(--color-text-secondary)"
          >
            <span
              aria-hidden="true"
              className={
                'size-1.5 rounded-full ' +
                (status.accepting ? 'bg-(--color-success)' : 'bg-(--color-text-muted)')
              }
            />
            {status.accepting ? 'Ready for connections' : 'Connections disabled'}
          </p>
        </div>
      </div>

      <div className="mx-[22px] h-px bg-(--color-separator)" />

      <dl className="px-[22px] py-2">
        <DeviceInfoRow
          label="Device ID"
          value={
            <span className="flex items-center gap-2">
              <span aria-label="Device ID" className="font-mono text-[14px] tracking-wide">
                {deviceId}
              </span>
              {deviceId !== '—' && <InlineCopy value={deviceId} label="device ID" />}
            </span>
          }
        />
        <DeviceInfoRow
          label="Network address"
          value={
            <span className="flex items-center gap-2">
              <span aria-label="Network address" className="font-mono text-[14px]">
                {primary ?? '—'}
              </span>
              {primary !== null && <InlineCopy value={primary} label="address" />}
            </span>
          }
        />
        <div className="flex min-h-9 items-center justify-between gap-4">
          <dt className="text-[14px] text-(--color-text-secondary)">Identity</dt>
          <dd>
            <button
              type="button"
              aria-expanded={advancedOpen}
              onClick={() => {
                setAdvancedOpen((open) => !open);
              }}
              className="flex items-center gap-1.5 text-[14px] text-(--color-text)"
            >
              <ShieldCheck aria-hidden="true" className="size-4 shrink-0 text-(--color-success)" />
              Verified
              <ChevronRight
                aria-hidden="true"
                className={
                  'size-4 text-(--color-text-muted) transition-transform duration-125 ' +
                  (advancedOpen ? 'rotate-90' : '')
                }
              />
            </button>
          </dd>
        </div>
      </dl>

      {advancedOpen && (
        <dl className="border-t border-(--color-separator) px-[22px] py-2">
          <DeviceInfoRow
            label="IPv4"
            value={
              displayIpv4(status.addresses) === '—'
                ? '—'
                : displayAddress(displayIpv4(status.addresses))
            }
          />
          {ipv6.map((address) => (
            <DeviceInfoRow key={address} label="IPv6" value={displayIpv6(address)} />
          ))}
          <DeviceInfoRow label="Hostname" value={hostname ?? '—'} />
          <DeviceInfoRow label="Listen port" value={String(status.listenPort)} />
          <DeviceInfoRow label="Connection method" value="Direct QUIC / TLS 1.3" />
          <DeviceInfoRow
            label="Local network"
            value={
              status.accepting
                ? `Listening on ${String(status.listenPort)}`
                : 'Not accepting connections'
            }
          />
          <DeviceInfoRow label="Relay" value="Not used — this build connects directly" />
        </dl>
      )}
    </Panel>
  );
}

function DeviceInfoRow({
  label,
  value,
}: {
  readonly label: string;
  readonly value: React.ReactNode;
}): React.JSX.Element {
  return (
    <div className="flex min-h-9 items-center justify-between gap-4">
      <dt className="text-[14px] text-(--color-text-secondary)">{label}</dt>
      <dd className="min-w-0 text-right font-mono text-[13px]">{value}</dd>
    </div>
  );
}

function InlineCopy({
  value,
  label,
}: {
  readonly value: string;
  readonly label: string;
}): React.JSX.Element {
  const [copied, setCopied] = useState(false);

  return (
    <button
      type="button"
      title={`Copy ${label}`}
      aria-label={`Copy ${label}`}
      onClick={() => {
        navigator.clipboard
          .writeText(value)
          .then(() => {
            setCopied(true);
            window.setTimeout(() => {
              setCopied(false);
            }, 1200);
          })
          .catch(() => {
            setCopied(false);
          });
      }}
      className="text-(--color-text-muted) hover:text-(--color-text)"
    >
      {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
    </button>
  );
}
