/**
 * Shortcuts into real features: unattended setup and sharing this machine.
 */

import { ChevronRight, Lock, UserPlus } from 'lucide-react';

import { Panel, PanelHeader } from './Panel';

export function QuickAccessPanel({
  onUnattended,
  onInvite,
}: {
  readonly onUnattended: () => void;
  readonly onInvite: () => void;
}): React.JSX.Element {
  return (
    <Panel>
      <PanelHeader title="Quick access" />
      <div className="flex min-h-0 flex-1 flex-col">
        <QuickAccessRow
          icon={Lock}
          label="Unattended Access"
          subtitle="Set up this device to access it remotely anytime."
          onClick={onUnattended}
        />
        <div className="mx-[22px] h-px shrink-0 bg-(--color-separator)" />
        <QuickAccessRow
          icon={UserPlus}
          label="Invite a contact"
          subtitle="Copy an invitation with this machine’s ID and address."
          onClick={onInvite}
        />
      </div>
    </Panel>
  );
}

function QuickAccessRow({
  icon: Icon,
  label,
  subtitle,
  onClick,
}: {
  readonly icon: typeof Lock;
  readonly label: string;
  readonly subtitle: string;
  readonly onClick: () => void;
}): React.JSX.Element {
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex min-h-[72px] w-full flex-1 items-center gap-4 px-[22px] text-left transition-colors duration-125 hover:bg-(--color-hover)"
    >
      <span className="flex size-10 shrink-0 items-center justify-center rounded-[4px] bg-(--color-hover) text-(--color-text-secondary)">
        <Icon aria-hidden="true" className="size-5" />
      </span>
      <span className="min-w-0 flex-1">
        <span className="block text-[15px] font-medium">{label}</span>
        <span className="mt-0.5 block text-[13px] text-(--color-text-muted)">{subtitle}</span>
      </span>
      <ChevronRight aria-hidden="true" className="size-4 shrink-0 text-(--color-text-muted)" />
    </button>
  );
}
