/**
 * The other machine: type an address, press Connect.
 *
 * The right card of the main window, and the one thing this application is for.
 *
 * # The field is never cleared on a failure
 *
 * A refusal, a typo and an unreachable machine all leave the address exactly as typed.
 * The user's next action is to correct or retry it, and clearing the field throws away
 * the thing they need. That is a deliberate rule, not an oversight.
 */

import { MonitorSmartphone } from 'lucide-react';
import { useState } from 'react';

import { parseAddress } from './address.js';
import { Button, Card, CardHeader, TextField } from './ui';

export function RemoteDeskCard({
  onConnect,
  busy,
  error,
}: {
  /** Given the canonical `host:port`. */
  readonly onConnect: (address: string) => void;
  readonly busy: boolean;
  /** A failure from the last attempt, shown under the field. */
  readonly error: string | null;
}): React.JSX.Element {
  const [text, setText] = useState('');
  const [refusal, setRefusal] = useState<string | null>(null);

  // The parser's reason takes precedence: it is about what is in the field right now,
  // whereas a backend error is about the previous attempt.
  const shown = refusal ?? error;

  const submit = (): void => {
    const parsed = parseAddress(text);
    if (!parsed.ok) {
      setRefusal(parsed.reason);
      return;
    }
    setRefusal(null);
    onConnect(parsed.value);
  };

  return (
    <Card>
      <CardHeader icon={MonitorSmartphone} title="Another desk" />

      <form
        onSubmit={(event) => {
          // Enter in the field submits, which is what anyone typing an address expects.
          event.preventDefault();
          submit();
        }}
      >
        <TextField
          label="Address"
          value={text}
          onChange={(value) => {
            setText(value);
            // Cleared as soon as they start fixing it; leaving it would have the field
            // contradicting itself while they type.
            setRefusal(null);
          }}
          placeholder="192.168.1.77"
          mono
          autoComplete="off"
          error={shown}
          help="The address shown on the other machine."
        />

        {/*
         * The label does not change while connecting. It is the accessible name of the
         * one action on this card, and swapping it for "Connecting…" renames the
         * control out from under anyone reading the window with a screen reader.
         * Disabling it is what stops a second attempt.
         */}
        <Button type="submit" variant="primary" className="mt-3 w-full" disabled={busy}>
          Connect
        </Button>
      </form>
    </Card>
  );
}
