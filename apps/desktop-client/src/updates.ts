/**
 * Update-flow rules shared by the update screen and the app shell.
 *
 * Kept free of React so the state-to-action mapping — the part that decides
 * which button a user sees and whether a background check may run — can be
 * tested directly.
 */

import type { UpdateState, UpdateStatus } from './api.js';

/** How often a running app looks for a new release. */
export const AUTO_CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000;

/** States where a transfer or installation is under way. */
const BUSY_STATES: ReadonlySet<UpdateState> = new Set<UpdateState>([
  'checking_for_updates',
  'preparing_download',
  'downloading',
  'paused',
  'waiting_for_network',
  'resuming',
  'verifying',
  'waiting_for_user_confirmation',
  'installing',
  'recovering',
]);

/** States whose status is worth re-reading on a timer. */
export const ACTIVE_STATES: ReadonlySet<UpdateState> = new Set<UpdateState>([
  ...BUSY_STATES,
  'ready_to_install',
]);

/**
 * Whether a silent background check may start.
 *
 * The backend refuses a check while a transfer or install is running, so the
 * watcher must not fire one and turn a routine poll into a visible error.
 */
export function canAutoCheck(state: UpdateState | null): boolean {
  return state !== null && !BUSY_STATES.has(state);
}

/** Whether an update is downloaded and waiting for the user to install it. */
export function isReadyToInstall(status: UpdateStatus | null): boolean {
  return status?.state === 'ready_to_install';
}

/**
 * The version to advertise in the app shell, or `null` to stay quiet.
 *
 * Only a genuinely newer, actionable version is announced: a failed check or a
 * mid-download state must not put a call to action in front of the user.
 */
export function pendingUpdateVersion(status: UpdateStatus | null): string | null {
  if (status?.availableVersion == null) return null;
  if (status.availableVersion === status.currentVersion) return null;
  return status.state === 'update_available' || status.state === 'ready_to_install'
    ? status.availableVersion
    : null;
}

export type PrimaryActionKind = 'check' | 'download' | 'install' | 'restart' | 'progress' | 'none';

export interface PrimaryAction {
  readonly kind: PrimaryActionKind;
  readonly label: string;
  /** Explains the current state under the button. */
  readonly detail: string;
  readonly disabled: boolean;
}

/**
 * The single action offered for a given status.
 *
 * One button whose meaning follows the state replaces the previous row of five
 * equally weighted buttons, four of which were disabled at any moment.
 */
export function primaryAction(status: UpdateStatus): PrimaryAction {
  const version = status.availableVersion ?? '';
  switch (status.state) {
    case 'idle':
      return {
        kind: 'check',
        label: 'Check for Updates',
        detail: `You are running version ${status.currentVersion}.`,
        disabled: false,
      };
    case 'checking_for_updates':
      return {
        kind: 'none',
        label: 'Checking…',
        detail: 'Looking for a newer release.',
        disabled: true,
      };
    case 'no_update_available':
      return {
        kind: 'check',
        label: 'Check Again',
        detail: `Version ${status.currentVersion} is the latest release.`,
        disabled: false,
      };
    case 'update_available':
      return {
        kind: 'download',
        label: `Update to ${version}`,
        detail: `Version ${version} is available.`,
        disabled: false,
      };
    case 'preparing_download':
    case 'resuming':
      return {
        kind: 'none',
        label: 'Starting…',
        detail: 'Preparing the download.',
        disabled: true,
      };
    case 'downloading':
      return {
        kind: 'progress',
        label: 'Downloading…',
        detail: `Downloading version ${version}.`,
        disabled: true,
      };
    case 'paused':
      return {
        kind: 'progress',
        label: 'Paused',
        detail: 'The download is paused.',
        disabled: true,
      };
    case 'waiting_for_network':
      return {
        kind: 'progress',
        label: 'Waiting for network…',
        detail: 'The download will continue when the connection returns.',
        disabled: true,
      };
    case 'verifying':
      return {
        kind: 'none',
        label: 'Verifying…',
        detail: 'Checking the download against its signature and checksum.',
        disabled: true,
      };
    case 'ready_to_install':
      return {
        kind: 'install',
        label: 'Install Now',
        detail: `Version ${version} is verified and ready to install.`,
        disabled: false,
      };
    case 'waiting_for_user_confirmation':
    case 'installing':
      return {
        kind: 'none',
        label: 'Installing…',
        detail: 'Installing the update.',
        disabled: true,
      };
    case 'restart_required':
      return {
        kind: 'restart',
        label: 'Restart to Finish',
        detail: 'The update is installed and applies after a restart.',
        disabled: false,
      };
    case 'completed':
      return {
        kind: 'check',
        label: 'Check for Updates',
        detail: 'The update finished successfully.',
        disabled: false,
      };
    case 'recovering':
      return {
        kind: 'none',
        label: 'Recovering…',
        detail: 'Restoring the previous version after a failed update.',
        disabled: true,
      };
    case 'failed':
      return {
        kind: 'check',
        label: 'Try Again',
        detail: status.lastError ?? 'The last update attempt failed.',
        disabled: false,
      };
  }
}

/** Whether pause/resume/cancel controls apply right now. */
export function transferControls(state: UpdateState): {
  readonly canPause: boolean;
  readonly canResume: boolean;
  readonly canCancel: boolean;
} {
  return {
    canPause: state === 'downloading',
    canResume: state === 'paused' || state === 'waiting_for_network',
    canCancel:
      state === 'downloading' ||
      state === 'paused' ||
      state === 'waiting_for_network' ||
      state === 'ready_to_install',
  };
}

/**
 * Split release notes into displayable bullets.
 *
 * Section headings produced by the release-notes generator are kept as
 * headings so the list does not read as one flat run of sentences.
 */
export function parseReleaseNotes(
  notes: string | null,
): readonly { readonly heading: string; readonly items: readonly string[] }[] {
  if (notes === null || notes.trim() === '') return [];
  const sections: { heading: string; items: string[] }[] = [];
  for (const rawLine of notes.split('\n')) {
    const line = rawLine.trim();
    if (line === '') continue;
    if (line.startsWith('- ')) {
      // Bullets before any heading belong to an unnamed leading section.
      const current = sections.at(-1) ?? { heading: '', items: [] };
      if (sections.length === 0) sections.push(current);
      current.items.push(line.slice(2).trim());
    } else {
      sections.push({ heading: line, items: [] });
    }
  }
  return sections.filter((section) => section.heading !== '' || section.items.length > 0);
}
