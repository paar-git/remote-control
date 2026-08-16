/**
 * A copy-to-clipboard button that confirms it worked.
 *
 * The labelled form, for toolbars and action rows. Inside a table of facts use
 * `InlineCopy`, which is the same behaviour in an icon that only appears on hover.
 */

import { Check, Copy } from 'lucide-react';
import { useState } from 'react';

import { Button } from './Button';

export function CopyButton({
  value,
  label,
  size = 'md',
}: {
  readonly value: string;
  readonly label: string;
  readonly size?: 'sm' | 'md' | undefined;
}): React.JSX.Element {
  const [copied, setCopied] = useState(false);

  return (
    <Button
      variant="ghost"
      size={size}
      icon={copied ? Check : Copy}
      title={`Copy ${label}`}
      onClick={() => {
        navigator.clipboard
          .writeText(value)
          .then(() => {
            setCopied(true);
            setTimeout(() => {
              setCopied(false);
            }, 1200);
          })
          .catch(() => {
            // Clipboard access can be refused; saying so beats failing silently.
            setCopied(false);
          });
      }}
    >
      {copied ? 'Copied' : 'Copy'}
    </Button>
  );
}
