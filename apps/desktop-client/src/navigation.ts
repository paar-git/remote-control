/**
 * The four categories the window is built around.
 *
 * Nothing else belongs in the sidebar. Session tools live inside a session; file
 * transfer is a permission, not a destination.
 */

import { Activity, HardDrive, MonitorSmartphone, Settings, type LucideIcon } from 'lucide-react';

export type View = 'remote-control' | 'my-devices' | 'sessions' | 'settings';

export const VIEWS: readonly { id: View; label: string; icon: LucideIcon }[] = [
  { id: 'remote-control', label: 'Remote Control', icon: MonitorSmartphone },
  { id: 'my-devices', label: 'My Devices', icon: HardDrive },
  { id: 'sessions', label: 'Sessions', icon: Activity },
  { id: 'settings', label: 'Settings', icon: Settings },
];
