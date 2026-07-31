/**
 * Application shell.
 *
 * At this phase the shell renders the navigation skeleton and a real status panel
 * fed by the `client_info` backend command. Navigation items whose features arrive in
 * later phases are rendered as disabled with the phase stated, rather than as buttons
 * that look live and do nothing.
 */

import { useEffect, useState } from 'react';

import { type ClientInfo, getClientInfo } from './api.js';
import { isTauriAvailable } from './ipc.js';

interface NavItem {
  readonly id: string;
  readonly label: string;
  /** `null` once the section is implemented. */
  readonly availableInPhase: number | null;
}

const NAV_ITEMS: readonly NavItem[] = [
  { id: 'home', label: 'Home', availableInPhase: null },
  { id: 'devices', label: 'Devices', availableInPhase: 2 },
  { id: 'remote-desktop', label: 'Remote Desktop', availableInPhase: 6 },
  { id: 'terminal', label: 'Terminal', availableInPhase: 4 },
  { id: 'files', label: 'Files', availableInPhase: 5 },
  { id: 'processes', label: 'Processes', availableInPhase: 7 },
  { id: 'services', label: 'Services', availableInPhase: 7 },
  { id: 'monitoring', label: 'Monitoring', availableInPhase: 4 },
  { id: 'power', label: 'Power', availableInPhase: 7 },
  { id: 'activity', label: 'Activity', availableInPhase: 7 },
  { id: 'settings', label: 'Settings', availableInPhase: 9 },
];

type LoadState =
  | { readonly status: 'loading' }
  | { readonly status: 'ready'; readonly info: ClientInfo }
  | { readonly status: 'error'; readonly message: string };

export default function App(): React.JSX.Element {
  const [state, setState] = useState<LoadState>({ status: 'loading' });

  useEffect(() => {
    let cancelled = false;

    if (!isTauriAvailable()) {
      setState({
        status: 'error',
        message:
          'The backend is not reachable. Run the app with `pnpm tauri:dev` rather than ' +
          'opening the dev server in a browser.',
      });
      return;
    }

    getClientInfo()
      .then((info) => {
        if (!cancelled) setState({ status: 'ready', info });
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setState({
          status: 'error',
          message: error instanceof Error ? error.message : 'Could not reach the backend.',
        });
      });

    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="flex h-full">
      <nav
        aria-label="Sections"
        className="flex w-56 shrink-0 flex-col border-r border-(--color-border-subtle) bg-(--color-surface-sunken)"
      >
        <div className="px-4 py-4">
          <h1 className="text-sm font-semibold">Remote Control</h1>
          <p className="text-xs text-(--color-text-secondary)">Private remote access</p>
        </div>

        <ul className="flex flex-col gap-0.5 px-2 pb-4">
          {NAV_ITEMS.map((item) => (
            <li key={item.id}>
              <button
                type="button"
                disabled={item.availableInPhase !== null}
                aria-current={item.id === 'home' ? 'page' : undefined}
                title={
                  item.availableInPhase === null
                    ? undefined
                    : `Arrives in development phase ${item.availableInPhase}`
                }
                className={
                  'flex w-full items-center justify-between rounded px-3 py-1.5 text-left text-sm ' +
                  (item.availableInPhase === null
                    ? 'bg-(--color-surface-raised) font-medium'
                    : 'cursor-not-allowed text-(--color-text-secondary) opacity-60')
                }
              >
                <span>{item.label}</span>
                {item.availableInPhase !== null && (
                  <span className="text-[10px] tabular-nums">P{item.availableInPhase}</span>
                )}
              </button>
            </li>
          ))}
        </ul>
      </nav>

      <main className="flex-1 overflow-auto p-6">
        <StatusPanel state={state} />
      </main>
    </div>
  );
}

function StatusPanel({ state }: { readonly state: LoadState }): React.JSX.Element {
  if (state.status === 'loading') {
    return (
      <p role="status" className="text-sm text-(--color-text-secondary)">
        Loading client information…
      </p>
    );
  }

  if (state.status === 'error') {
    return (
      <div role="alert" className="max-w-prose rounded border border-(--color-danger) p-4 text-sm">
        <h2 className="mb-1 font-semibold text-(--color-danger)">Backend unavailable</h2>
        <p className="text-(--color-text-secondary)">{state.message}</p>
      </div>
    );
  }

  const { info } = state;
  const rows: readonly (readonly [string, string])[] = [
    ['App version', info.appVersion],
    ['Protocol', `${String(info.protocolVersion.major)}.${String(info.protocolVersion.minor)}`],
    ['Hostname', info.hostname],
    ['Operating system', `${info.osVersion} (${info.osFamily})`],
    ['Architecture', info.architecture],
    ['Running elevated', info.elevated ? 'yes' : 'no'],
    ['Local database', info.databaseReady ? 'ready' : 'unavailable'],
  ];

  return (
    <section>
      <h2 className="mb-1 text-base font-semibold">This computer</h2>
      <p className="mb-4 max-w-prose text-sm text-(--color-text-secondary)">
        The client is running and its local database is migrated. Pairing and the saved-device list
        arrive in phase 2; see <code>PROGRESS.md</code>.
      </p>

      <dl className="max-w-md divide-y divide-(--color-border-subtle) rounded border border-(--color-border-subtle)">
        {rows.map(([label, value]) => (
          <div key={label} className="flex justify-between gap-4 px-3 py-2 text-sm">
            <dt className="text-(--color-text-secondary)">{label}</dt>
            <dd className="font-mono">{value}</dd>
          </div>
        ))}
      </dl>

      {info.elevated && (
        <p role="alert" className="mt-4 max-w-prose text-sm text-(--color-warning)">
          This client is running with administrator privileges. That is not required and not
          recommended — privileged operations are routed through the agent service instead.
        </p>
      )}
    </section>
  );
}
