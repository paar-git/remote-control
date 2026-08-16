import { describe, expect, it } from 'vitest';

import type { UpdateState, UpdateStatus } from './api.js';
import {
  canAutoCheck,
  parseReleaseNotes,
  pendingUpdateVersion,
  primaryAction,
  transferControls,
} from './updates.js';

function status(overrides: Partial<UpdateStatus> = {}): UpdateStatus {
  return {
    state: 'idle',
    manifestUrl: null,
    currentVersion: '0.1.0',
    availableVersion: null,
    releaseNotes: null,
    platform: {
      os: 'windows',
      osVersion: '10.0.26200',
      cpuArchitecture: 'x64',
      installationArchitecture: 'x64',
      key: 'windows-x64',
      installationType: 'windows-msi',
    },
    packageFormat: null,
    download: null,
    readyPath: null,
    lastError: null,
    ...overrides,
  };
}

const ALL_STATES: readonly UpdateState[] = [
  'idle',
  'checking_for_updates',
  'no_update_available',
  'update_available',
  'preparing_download',
  'downloading',
  'paused',
  'waiting_for_network',
  'resuming',
  'verifying',
  'ready_to_install',
  'waiting_for_user_confirmation',
  'installing',
  'restart_required',
  'completed',
  'failed',
  'recovering',
];

describe('primaryAction', () => {
  it('offers exactly one action for every backend state', () => {
    for (const state of ALL_STATES) {
      const action = primaryAction(status({ state }));
      expect(action.label, `state ${state} must have a label`).not.toBe('');
      expect(action.detail, `state ${state} must explain itself`).not.toBe('');
    }
  });

  it('names the target version on the download button', () => {
    const action = primaryAction(status({ state: 'update_available', availableVersion: '0.1.1' }));
    expect(action.kind).toBe('download');
    expect(action.label).toBe('Update to 0.1.1');
  });

  it('offers installation only once the download is verified', () => {
    expect(primaryAction(status({ state: 'downloading' })).kind).not.toBe('install');
    expect(primaryAction(status({ state: 'verifying' })).kind).not.toBe('install');
    expect(primaryAction(status({ state: 'ready_to_install' })).kind).toBe('install');
  });

  it('shows the failure reason instead of a bare error label', () => {
    const action = primaryAction(
      status({ state: 'failed', lastError: 'The signature did not verify.' }),
    );
    expect(action.kind).toBe('check');
    expect(action.detail).toBe('The signature did not verify.');
  });

  it('falls back to a generic reason when a failure carries no message', () => {
    expect(primaryAction(status({ state: 'failed' })).detail).toBe(
      'The last update attempt failed.',
    );
  });

  it('disables the action while work is in progress', () => {
    for (const state of ['checking_for_updates', 'installing', 'verifying'] as const) {
      expect(primaryAction(status({ state })).disabled, state).toBe(true);
    }
  });

  it('asks for a restart once the install has landed', () => {
    expect(primaryAction(status({ state: 'restart_required' })).kind).toBe('restart');
  });
});

describe('canAutoCheck', () => {
  it('permits a background check only when nothing is in flight', () => {
    for (const state of [
      'idle',
      'no_update_available',
      'update_available',
      'completed',
      'failed',
      'restart_required',
    ] as const) {
      expect(canAutoCheck(state), state).toBe(true);
    }
  });

  it('refuses to interrupt a transfer or an installation', () => {
    for (const state of [
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
    ] as const) {
      expect(canAutoCheck(state), state).toBe(false);
    }
  });

  it('does not check before a status has been read', () => {
    expect(canAutoCheck(null)).toBe(false);
  });
});

describe('pendingUpdateVersion', () => {
  it('announces an available version', () => {
    expect(
      pendingUpdateVersion(status({ state: 'update_available', availableVersion: '0.1.1' })),
    ).toBe('0.1.1');
  });

  it('announces a verified update that is waiting to install', () => {
    expect(
      pendingUpdateVersion(status({ state: 'ready_to_install', availableVersion: '0.1.1' })),
    ).toBe('0.1.1');
  });

  it('stays quiet when the app is already current', () => {
    expect(pendingUpdateVersion(status({ state: 'no_update_available' }))).toBeNull();
    expect(
      pendingUpdateVersion(
        status({ state: 'update_available', availableVersion: '0.1.0', currentVersion: '0.1.0' }),
      ),
    ).toBeNull();
  });

  it('stays quiet before any status is known', () => {
    expect(pendingUpdateVersion(null)).toBeNull();
  });

  it('does not advertise an update mid-download or after a failure', () => {
    for (const state of ['downloading', 'failed', 'installing'] as const) {
      expect(pendingUpdateVersion(status({ state, availableVersion: '0.1.1' })), state).toBeNull();
    }
  });
});

describe('transferControls', () => {
  it('offers pause only while downloading', () => {
    expect(transferControls('downloading').canPause).toBe(true);
    expect(transferControls('paused').canPause).toBe(false);
  });

  it('offers resume when the transfer is stalled or paused', () => {
    expect(transferControls('paused').canResume).toBe(true);
    expect(transferControls('waiting_for_network').canResume).toBe(true);
    expect(transferControls('downloading').canResume).toBe(false);
  });

  it('never offers to cancel an installation in progress', () => {
    expect(transferControls('installing').canCancel).toBe(false);
    expect(transferControls('downloading').canCancel).toBe(true);
  });
});

describe('parseReleaseNotes', () => {
  it('groups bullets under their headings', () => {
    const sections = parseReleaseNotes(
      'Features\n- Added a thing\n- Added another\n\nFixes\n- Fixed a thing',
    );
    expect(sections).toEqual([
      { heading: 'Features', items: ['Added a thing', 'Added another'] },
      { heading: 'Fixes', items: ['Fixed a thing'] },
    ]);
  });

  it('keeps bullets that appear before any heading', () => {
    expect(parseReleaseNotes('- Just one change')).toEqual([
      { heading: '', items: ['Just one change'] },
    ]);
  });

  it('returns nothing for absent or blank notes', () => {
    expect(parseReleaseNotes(null)).toEqual([]);
    expect(parseReleaseNotes('   \n  ')).toEqual([]);
  });

  it('keeps a plain prose note readable', () => {
    expect(parseReleaseNotes('Improved performance and fixed crashes.')).toEqual([
      { heading: 'Improved performance and fixed crashes.', items: [] },
    ]);
  });
});
