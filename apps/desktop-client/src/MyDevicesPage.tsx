/**
 * Trusted computers, with a real presence probe for each one that has an address.
 */

import { useCallback, useEffect, useState } from 'react';

import {
  connectToAddress,
  listTrustedDevices,
  probeDevice,
  type Presence,
  type TrustedDevice,
} from './api.js';
import { DeviceCard } from './DeviceCard';
import { DeviceDetail } from './DeviceDetail';
import { EmptyState, PageHeader, type Toast } from './ui';

export function MyDevicesPage({
  onConnect,
  onToast,
}: {
  readonly onConnect: () => void;
  readonly onToast: (toast: Toast) => void;
}): React.JSX.Element {
  const [devices, setDevices] = useState<readonly TrustedDevice[] | null>(null);
  const [presence, setPresence] = useState<Readonly<Record<string, Presence>>>({});
  const [open, setOpen] = useState<TrustedDevice | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    listTrustedDevices()
      .then((loaded) => {
        setDevices(loaded);
        for (const device of loaded) {
          if (device.lastAddress === null) {
            setPresence((current) => ({ ...current, [device.identityFingerprint]: 'offline' }));
            continue;
          }
          setPresence((current) => ({ ...current, [device.identityFingerprint]: 'checking' }));
          probeDevice(device.lastAddress)
            .then((result) => {
              setPresence((current) => ({ ...current, [device.identityFingerprint]: result }));
            })
            .catch(() => {
              setPresence((current) => ({ ...current, [device.identityFingerprint]: 'offline' }));
            });
        }
      })
      .catch((error: unknown) => {
        onToast({
          kind: 'error',
          message: error instanceof Error ? error.message : 'Could not load trusted devices.',
        });
        setDevices([]);
      });
  }, [onToast]);

  useEffect(() => {
    load();
  }, [load]);

  const connect = (device: TrustedDevice): void => {
    if (device.lastAddress === null) return;
    setBusy(true);
    connectToAddress(device.lastAddress, null)
      .then(() => {
        onConnect();
      })
      .catch((error: unknown) => {
        onToast({
          kind: 'error',
          message: error instanceof Error ? error.message : 'Could not start the connection.',
        });
      })
      .finally(() => {
        setBusy(false);
      });
  };

  return (
    <div className="mx-auto w-full max-w-4xl">
      <PageHeader
        title="My Devices"
        description="Computers this machine trusts. Access and permissions are decided separately."
      />

      {devices === null ? (
        <p className="text-sm text-(--color-text-secondary)">Loading trusted devices…</p>
      ) : devices.length === 0 ? (
        <EmptyState
          title="No trusted devices yet"
          body="Accept & Trust on an incoming connection, or connect to a machine and remember it."
        />
      ) : (
        <div className="grid gap-4 sm:grid-cols-2">
          {devices.map((device) => (
            <DeviceCard
              key={device.identityFingerprint}
              device={device}
              presence={presence[device.identityFingerprint] ?? 'checking'}
              busy={busy}
              onConnect={() => {
                connect(device);
              }}
              onOpen={() => {
                setOpen(device);
              }}
            />
          ))}
        </div>
      )}

      {open !== null && (
        <DeviceDetail
          device={
            devices?.find((item) => item.identityFingerprint === open.identityFingerprint) ?? open
          }
          presence={presence[open.identityFingerprint] ?? 'checking'}
          onChanged={load}
          onClose={() => {
            setOpen(null);
          }}
          onToast={onToast}
        />
      )}
    </div>
  );
}
