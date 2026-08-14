/**
 * The second step required to grant Administrator.
 *
 * Naming the device and listing the privileges is the whole point: a permission that
 * lets a device rewrite the trust database must not be reachable from a switch alone.
 */

import { useEffect, useRef } from 'react';

import type { TrustedDevice } from './api.js';
import { Button } from './ui';

export function GrantAdminDialog({
  device,
  onConfirm,
  onCancel,
}: {
  readonly device: TrustedDevice;
  readonly onConfirm: () => void;
  readonly onCancel: () => void;
}): React.JSX.Element {
  const cancelRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    cancelRef.current?.focus();
    const onKey = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') onCancel();
    };
    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('keydown', onKey);
    };
  }, [onCancel]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-[rgb(16_24_40_/_40%)] p-4 backdrop-blur-[2px]">
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Grant Administrator Access?"
        className="w-full max-w-md rounded-xl border border-(--color-border) bg-(--color-card) p-5 shadow-xl"
      >
        <h2 className="mb-2 text-base font-semibold">Grant Administrator Access?</h2>
        <p className="mb-3 text-sm text-(--color-text-secondary)">
          {device.displayName} will be able to manage this machine’s trusted devices. That includes:
        </p>
        <ul className="mb-5 list-disc space-y-1 pl-5 text-sm text-(--color-text-secondary)">
          <li>See every device you trust and how far</li>
          <li>Change another device’s permissions</li>
          <li>Grant or withdraw unattended access</li>
          <li>Suspend or revoke a device</li>
        </ul>
        <div className="flex justify-end gap-2">
          <Button ref={cancelRef} variant="default" onClick={onCancel}>
            Cancel
          </Button>
          <Button variant="danger" onClick={onConfirm}>
            Grant Administrator Access
          </Button>
        </div>
      </div>
    </div>
  );
}
