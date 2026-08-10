/**
 * Remote Support — connect with a one-time access code.
 *
 * Chrome Remote Desktop's support flow in the shape this app can honestly support: the
 * person at the other computer runs `rc-agent pair`, reads out the code it prints, and
 * you type it here. The code is single-use, expires in three minutes, and is spent on
 * the first attempt — which is why the format is checked locally as you type rather than
 * by burning an attempt on a typo.
 *
 * What this screen does *not* have is a "Share this screen" half. This application is
 * the client; it has no host-side sharing to offer, and a button that generated a code
 * nobody could use would be a lie in the shape of a feature.
 */

import { Radar, ShieldCheck } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';

import {
  type DiscoveredAgent,
  checkPairingCodeFormat,
  discoverAgents,
  pairWithServer,
} from './api.js';
import {
  Button,
  Card,
  EmptyState,
  PageHeader,
  StatusBadge,
  TextField,
  Tooltip,
  type Toast,
} from './ui';

export function RemoteSupportScreen({
  onToast,
  onPaired,
}: {
  readonly onToast: (toast: Toast) => void;
  /** Called after a successful pairing, so the device list can pick it up. */
  readonly onPaired: () => void;
}): React.JSX.Element {
  const [address, setAddress] = useState('');
  const [name, setName] = useState('');
  const [code, setCode] = useState('');
  const [formatOk, setFormatOk] = useState<boolean | null>(null);
  const [pairing, setPairing] = useState(false);
  const [found, setFound] = useState<readonly DiscoveredAgent[] | null>(null);
  const [searching, setSearching] = useState(false);

  useEffect(() => {
    if (code.trim() === '') {
      setFormatOk(null);
      return;
    }
    let cancelled = false;
    checkPairingCodeFormat(code)
      .then((ok) => {
        if (!cancelled) setFormatOk(ok);
      })
      .catch(() => {
        if (!cancelled) setFormatOk(null);
      });
    return () => {
      cancelled = true;
    };
  }, [code]);

  const search = useCallback(() => {
    setSearching(true);
    discoverAgents()
      .then(setFound)
      .catch((error: unknown) => {
        onToast({
          kind: 'error',
          message: error instanceof Error ? error.message : 'Could not search the local network.',
        });
      })
      .finally(() => {
        setSearching(false);
      });
  }, [onToast]);

  const submit = useCallback(() => {
    setPairing(true);
    pairWithServer(address, code, name)
      .then((paired) => {
        setCode('');
        setAddress('');
        setName('');
        setFound(null);
        onToast({
          kind: 'success',
          message: `Added ${paired.displayName}. Check its fingerprint matches the computer: ${paired.identityFingerprint}`,
        });
        onPaired();
      })
      .catch((error: unknown) => {
        onToast({
          kind: 'error',
          message: error instanceof Error ? error.message : 'That code was not accepted.',
        });
      })
      .finally(() => {
        setPairing(false);
      });
  }, [address, code, name, onPaired, onToast]);

  const canSubmit = !pairing && formatOk === true && address.trim() !== '';

  return (
    <div className="animate-fade-in mx-auto flex w-full max-w-xl flex-col gap-6">
      <PageHeader
        title="Remote Support"
        description="Add a computer using a one-time access code. Codes are single-use and expire after three minutes."
      />

      <Card className="p-5!">
        <h3 className="text-sm font-semibold">Connect to another computer</h3>
        <p className="mt-1 text-sm text-(--color-text-secondary)">
          On the other computer, run <code className="font-mono text-xs">rc-agent pair</code> and
          read the code it prints.
        </p>

        <form
          className="mt-5 flex flex-col gap-4"
          onSubmit={(event) => {
            event.preventDefault();
            if (canSubmit) submit();
          }}
        >
          <TextField
            label="Computer address"
            value={address}
            onChange={setAddress}
            placeholder="192.168.1.20"
            autoComplete="off"
            mono
          />

          <TextField
            label="Access code"
            value={code}
            onChange={setCode}
            placeholder="XXX-XXX-XXX"
            maxLength={16}
            autoComplete="off"
            mono
            uppercase
            error={formatOk === false ? 'That is not a valid access code.' : null}
            help={
              formatOk === true
                ? 'Valid format.'
                : 'Nine characters. The letters and digits 0 1 I L O U are never used, so there is nothing to mistype.'
            }
          />

          <TextField
            label="Name it"
            value={name}
            onChange={setName}
            placeholder="Home server"
            maxLength={64}
            help="What this computer will be called in your list. Optional."
          />

          <Button type="submit" variant="primary" disabled={!canSubmit} className="h-10 w-full">
            {pairing ? 'Connecting…' : 'Connect'}
          </Button>
        </form>

        <p className="mt-4 flex items-start gap-2 text-xs text-(--color-text-muted)">
          <ShieldCheck aria-hidden="true" className="mt-px size-3.5 shrink-0" />
          After pairing, compare the fingerprint shown with the one printed on the other computer.
          That comparison is what confirms you paired with the machine you meant to.
        </p>
      </Card>

      <Card>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="min-w-0">
            <h3 className="text-sm font-semibold">Find computers on this network</h3>
            <p className="mt-0.5 text-sm text-(--color-text-secondary)">
              Fills in the address for you. You still need the access code.
            </p>
          </div>
          <Button icon={Radar} onClick={search} disabled={searching}>
            {searching ? 'Searching…' : 'Search'}
          </Button>
        </div>

        {found !== null && found.length === 0 && (
          <div className="mt-4">
            <EmptyState
              icon={Radar}
              title="Nothing answered"
              body="Many networks block discovery. Type the computer’s address above instead."
            />
          </div>
        )}

        {found !== null && found.length > 0 && (
          <ul className="mt-4 flex flex-col gap-1.5">
            {found.map((agent) => (
              <li
                key={agent.deviceId}
                className="flex flex-wrap items-center gap-2.5 rounded-lg border border-(--color-border-subtle) bg-(--color-surface) px-3 py-2 text-xs"
              >
                {/* Every field here is a claim: anyone on the network can announce
                    anything. It is a convenience for filling in the address, never a
                    statement about identity. */}
                <Tooltip label="Announced by the computer itself, and not verified until you pair">
                  <span className="font-medium">{agent.displayName}</span>
                </Tooltip>
                <span className="font-mono text-(--color-text-secondary)">{agent.address}</span>
                <span className="flex-1" />
                {agent.alreadySaved ? (
                  <StatusBadge tone="ready">Already added</StatusBadge>
                ) : (
                  <Button
                    size="sm"
                    onClick={() => {
                      setAddress(agent.address);
                      setName(agent.displayName);
                    }}
                  >
                    Use this
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
