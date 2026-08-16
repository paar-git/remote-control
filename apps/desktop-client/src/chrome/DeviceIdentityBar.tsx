/**
 * This machine's address: the large Device ID plus copy / share / invite.
 */

import { Check, Copy, Info, Share2, UserPlus } from 'lucide-react';
import { useState } from 'react';

import type { HostStatus, LocalIdentity } from '../api.js';
import { formatDeviceId } from '../format.js';
import { Tooltip } from '../ui/Tooltip';
import { primaryAddress } from './addressHelpers';

export function DeviceIdentityBar({
  status,
  identity,
  onInvite,
}: {
  readonly status: HostStatus | null;
  readonly identity: LocalIdentity | null;
  readonly onInvite: () => void;
}): React.JSX.Element {
  const deviceId = identity === null ? '—' : formatDeviceId(identity.identityFingerprint);
  const address = status === null ? null : primaryAddress(status.addresses);

  return (
    <section className="shrink-0 py-4">
      <div className="rc-content">
        <div className="grid h-[91px] grid-cols-[1fr_auto_1fr] items-center gap-4 rounded-[4px] border border-(--color-border) bg-(--color-page) px-6 max-[1100px]:h-auto max-[1100px]:grid-cols-1 max-[1100px]:justify-items-center max-[1100px]:gap-3 max-[1100px]:py-4">
          <div className="flex items-center gap-2">
            <p className="text-[17px] font-medium text-(--color-text)">Your Address</p>
            <Tooltip
              label="This number identifies this machine. The other person connects with the hostname or IP address, not this number."
              side="bottom"
            >
              <span className="text-(--color-text-muted)">
                <Info aria-label="About your address" className="size-[18px]" />
              </span>
            </Tooltip>
          </div>

          <p
            aria-label="Device ID"
            className="text-center font-mono text-[42px] leading-none font-semibold tracking-[0.08em] text-(--color-accent) max-[1100px]:text-[32px]"
          >
            {deviceId}
          </p>

          <div className="flex items-center justify-end gap-3">
            <CopyAction value={deviceId} disabled={deviceId === '—'} />
            <ShareAction
              machineName={status?.machineName ?? 'This device'}
              deviceId={deviceId}
              address={address}
            />
            <button
              type="button"
              onClick={onInvite}
              className="inline-flex h-10 w-[123px] items-center justify-center gap-1.5 rounded-[4px] border border-(--color-accent) bg-transparent text-[14px] font-medium text-(--color-accent) hover:bg-(--color-accent-soft)"
            >
              <UserPlus aria-hidden="true" className="size-4" />
              Invite
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}

function CopyAction({
  value,
  disabled,
}: {
  readonly value: string;
  readonly disabled: boolean;
}): React.JSX.Element {
  const [copied, setCopied] = useState(false);

  return (
    <button
      type="button"
      title="Copy device ID"
      disabled={disabled}
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
      className="inline-flex items-center gap-1.5 px-1 text-[14px] text-(--color-text-secondary) hover:text-(--color-text) disabled:opacity-45"
    >
      {copied ? <Check className="size-4" /> : <Copy className="size-4" />}
      {copied ? 'Copied' : 'Copy'}
    </button>
  );
}

function ShareAction({
  machineName,
  deviceId,
  address,
}: {
  readonly machineName: string;
  readonly deviceId: string;
  readonly address: string | null;
}): React.JSX.Element {
  const [shared, setShared] = useState(false);

  return (
    <button
      type="button"
      onClick={() => {
        const text = invitationText(machineName, deviceId, address);
        navigator.clipboard.writeText(text).then(
          () => {
            setShared(true);
            window.setTimeout(() => {
              setShared(false);
            }, 1200);
          },
          () => {
            setShared(false);
          },
        );
      }}
      className="inline-flex items-center gap-1.5 px-1 text-[14px] text-(--color-text-secondary) hover:text-(--color-text)"
    >
      <Share2 className="size-4" />
      {shared ? 'Copied' : 'Share'}
    </button>
  );
}

export function invitationText(
  machineName: string,
  deviceId: string,
  address: string | null,
): string {
  return [
    `Connect to ${machineName} on RC`,
    `Device ID: ${deviceId}`,
    ...(address === null ? [] : [`Address: ${address}`]),
  ].join('\n');
}
