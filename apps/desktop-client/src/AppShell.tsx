/**
 * Persistent chrome: title bar, connect row, identity, horizontal nav, status.
 */

import type { ConnectionState, HostStatus, LocalIdentity, Recent } from './api.js';
import {
  AppTitleBar,
  BottomStatusBar,
  ConnectionBar,
  DeviceIdentityBar,
  MainNavigation,
} from './chrome';
import type { View } from './navigation.js';

export function AppShell({
  view,
  onNavigate,
  banner,
  children,
  connection,
  status,
  identity,
  recent,
  address,
  onAddressChange,
  onSubmit,
  parseError,
  busy,
  failed,
  inputRef,
  onPickRecent,
  onConnectWithPassword,
  onNewSession,
  onInvite,
}: {
  readonly view: View;
  readonly onNavigate: (view: View) => void;
  readonly banner: React.ReactNode;
  readonly children: React.ReactNode;
  readonly connection: ConnectionState;
  readonly status: HostStatus | null;
  readonly identity: LocalIdentity | null;
  readonly recent: readonly Recent[];
  readonly address: string;
  readonly onAddressChange: (value: string) => void;
  readonly onSubmit: () => void;
  readonly parseError: string | null;
  readonly busy: boolean;
  readonly failed: boolean;
  readonly inputRef: React.RefObject<HTMLInputElement | null>;
  readonly onPickRecent: (target: string) => void;
  readonly onConnectWithPassword: (password: string) => void;
  readonly onNewSession: () => void;
  readonly onInvite: () => void;
}): React.JSX.Element {
  return (
    <div className="flex h-full min-h-0 flex-col bg-(--color-page)">
      <AppTitleBar onNewSession={onNewSession} />
      <ConnectionBar
        address={address}
        onAddressChange={onAddressChange}
        onSubmit={onSubmit}
        parseError={parseError}
        busy={busy}
        failed={failed}
        connection={connection}
        recent={recent}
        inputRef={inputRef}
        onPickRecent={onPickRecent}
        onConnectWithPassword={onConnectWithPassword}
        onNavigate={onNavigate}
      />
      <DeviceIdentityBar status={status} identity={identity} onInvite={onInvite} />
      <MainNavigation view={view} onNavigate={onNavigate} />
      {banner}
      <main
        key={view}
        className={
          'animate-view-in min-h-0 flex-1 pt-2 pb-3 ' +
          (view === 'remote-control' ? 'flex flex-col overflow-hidden' : 'overflow-y-auto')
        }
      >
        <div
          className={
            view === 'remote-control' ? 'rc-content flex min-h-0 flex-1 flex-col' : 'rc-content'
          }
        >
          {children}
        </div>
      </main>
      <BottomStatusBar status={status} connection={connection} />
    </div>
  );
}
