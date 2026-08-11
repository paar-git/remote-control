/**
 * The navigation model.
 *
 * One table describes every section: where it sits, what it is called, what it is for,
 * whether it is built, and which key selects it. The sidebar, the keyboard shortcuts and
 * the screens themselves all read from here, so a section cannot appear in one and be
 * missing from another.
 *
 * The shape follows Chrome Remote Desktop's split — **Remote Access** for the machines
 * you have saved, **Remote Support** for a one-time code — with the session tools grouped
 * beneath, because they are only useful once a session is open. Remote Desktop is not a
 * section: connecting to a computer *is* the remote desktop, and it takes over the whole
 * window rather than living in the sidebar.
 *
 * `availableInPhase` records the truth for developers — which development phase builds
 * the section — while `UNAVAILABLE_REASON` is what the interface actually says. The
 * operator of a shipped build has no use for the project's phase numbering.
 */

import {
  Activity,
  Blocks,
  Cpu,
  DownloadCloud,
  Folder,
  History,
  MonitorSmartphone,
  Power,
  Settings,
  type LucideIcon,
} from 'lucide-react';

export interface NavItem {
  readonly id: string;
  readonly label: string;
  readonly icon: LucideIcon;
  /** One line describing what the section does. Used in tooltips. */
  readonly description: string;
  /** `null` once the section is implemented. */
  readonly availableInPhase: number | null;
  /** A shortcut, only where one is actually bound. */
  readonly shortcut?: string;
  /** Whether the section needs a live session to do anything. */
  readonly needsSession?: boolean;
}

export interface NavGroup {
  readonly id: string;
  readonly label: string;
  readonly items: readonly NavItem[];
}

/** What the interface says about a section that has not been built yet. */
export const UNAVAILABLE_REASON = 'Not available in this version yet';

/** What the interface says about a built section that has nothing to talk to. */
export const NO_SESSION_REASON = 'Connect to a computer first';

/** The section the app opens on. */
export const DEFAULT_SECTION = 'remote-access';

export const NAV_GROUPS: readonly NavGroup[] = [
  {
    id: 'remote',
    label: 'Remote',
    items: [
      {
        id: 'remote-access',
        label: 'Remote Access',
        icon: MonitorSmartphone,
        description: 'Your saved computers',
        availableInPhase: null,
        shortcut: 'Ctrl+1',
      },
    ],
  },
  {
    id: 'session',
    label: 'Session tools',
    items: [
      {
        id: 'files',
        label: 'Files',
        icon: Folder,
        description: 'Browse and transfer files',
        availableInPhase: null,
        shortcut: 'Ctrl+3',
        needsSession: true,
      },
      {
        id: 'monitoring',
        label: 'Monitoring',
        icon: Activity,
        description: 'Live CPU, memory, disk and network',
        availableInPhase: null,
        shortcut: 'Ctrl+4',
        needsSession: true,
      },
      {
        id: 'processes',
        label: 'Processes',
        icon: Cpu,
        description: 'Inspect and end running processes',
        availableInPhase: 7,
      },
      {
        id: 'services',
        label: 'Services',
        icon: Blocks,
        description: 'Start, stop and inspect services',
        availableInPhase: 7,
      },
      {
        id: 'power',
        label: 'Power',
        icon: Power,
        description: 'Restart, shut down and sign out',
        availableInPhase: 7,
      },
    ],
  },
  {
    id: 'this-computer',
    label: 'This computer',
    items: [
      {
        id: 'this-computer',
        label: 'Identity',
        icon: Settings,
        description: 'This computer’s identity, security and details',
        availableInPhase: null,
        shortcut: 'Ctrl+5',
      },
      {
        id: 'activity',
        label: 'Activity',
        icon: History,
        description: 'What this client has done, and when',
        availableInPhase: 7,
      },
      {
        id: 'updates',
        label: 'Updates',
        icon: DownloadCloud,
        description: 'Check for and install new versions',
        availableInPhase: null,
        shortcut: 'Ctrl+6',
      },
    ],
  },
];

/** Every item, flattened, in sidebar order. */
export const NAV_ITEMS: readonly NavItem[] = NAV_GROUPS.flatMap((group) => group.items);

/** Look up one item. Returns `undefined` for an id that is not a section. */
export function findNavItem(id: string): NavItem | undefined {
  return NAV_ITEMS.find((item) => item.id === id);
}

/** Whether a section is built and can be opened. */
export function isSectionAvailable(id: string): boolean {
  return findNavItem(id)?.availableInPhase === null;
}

/** The section a shortcut selects, or `undefined` if the combination is not bound. */
export function sectionForShortcut(event: KeyboardEvent): string | undefined {
  if (!event.ctrlKey || event.altKey || event.shiftKey || event.metaKey) return undefined;
  return NAV_ITEMS.find(
    (item) => item.shortcut === `Ctrl+${event.key}` && item.availableInPhase === null,
  )?.id;
}
