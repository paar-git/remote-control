/**
 * Human labels for values the interface already understands.
 *
 * Kept in one place so a permission is never called two things on two screens.
 */

import type { Permission } from './api.js';

/** The four permissions a human can grant from the Accept dialog or a device card. */
export const GRANTABLE_PERMISSIONS: readonly {
  readonly id: Exclude<Permission, 'administer'>;
  readonly label: string;
}[] = [
  { id: 'view_screen', label: 'Screen Viewing' },
  { id: 'control_input', label: 'Keyboard & Mouse' },
  { id: 'transfer_files', label: 'File Transfer' },
  { id: 'view_metrics', label: 'System Metrics' },
];

/** What a permission is called in the interface. */
export function permissionLabel(permission: Permission): string {
  switch (permission) {
    case 'view_screen':
      return 'Screen Viewing';
    case 'control_input':
      return 'Keyboard & Mouse';
    case 'transfer_files':
      return 'File Transfer';
    case 'view_metrics':
      return 'System Metrics';
    case 'administer':
      return 'Administrator Access';
  }
}

/** A readable operating-system name from the family the peer reported. */
export function osLabel(family: string): string {
  switch (family.toLowerCase()) {
    case 'windows':
      return 'Windows';
    case 'linux':
      return 'Linux';
    case 'macos':
      return 'macOS';
    case 'unknown':
    case '':
      return 'Unknown';
    default:
      return family;
  }
}
