/**
 * The Terminal screen.
 *
 * A real terminal emulator (xterm.js) attached to a real PTY on the server. Bytes go
 * from the emulator to the shell and back unaltered — which is why colours, line
 * editing, interactive prompts and full-screen programs work without this screen
 * knowing anything about them.
 *
 * # This screen must answer the shell's questions
 *
 * A shell asks the terminal about itself before drawing a prompt — most visibly
 * `ESC[6n`, "where is the cursor?". xterm.js answers those automatically as part of
 * processing the stream, which is precisely why a real emulator is used rather than a
 * `<pre>` with the escape codes stripped. Stripping them would produce something that
 * looked like a terminal and hung on the first prompt.
 *
 * # Nothing typed here is stored
 *
 * Input and output pass through without being logged, kept in application state, or
 * written anywhere. A terminal is where passwords are typed.
 */

import { FitAddon } from '@xterm/addon-fit';
import { Terminal } from '@xterm/xterm';
import { Plus, SquareTerminal, X } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';

import '@xterm/xterm/css/xterm.css';

import {
  type OpenedTerminal,
  closeTerminal,
  listenTerminalExit,
  listenTerminalOutput,
  openTerminal,
  resizeTerminal,
  sendTerminalInput,
} from './api.js';
import { Badge, Button, EmptyState, PageHeader, SelectField, StatusBadge, type Toast } from './ui';

/** Shells the operator can pick. */
const SHELLS = [
  { id: 'default', label: 'Default shell' },
  { id: 'powershell', label: 'PowerShell' },
  { id: 'cmd', label: 'Command Prompt' },
  { id: 'bash', label: 'Bash' },
] as const;

/** One open tab. */
interface Tab {
  readonly id: string;
  readonly title: string;
  readonly shellPath: string;
  readonly pid: number;
  readonly elevated: boolean;
  exited: boolean;
}

export default function TerminalScreen({
  onToast,
}: {
  readonly onToast: (toast: Toast) => void;
}): React.JSX.Element {
  const [tabs, setTabs] = useState<Tab[]>([]);
  const [active, setActive] = useState<string | null>(null);
  const [shell, setShell] = useState<string>('default');
  const [opening, setOpening] = useState(false);

  const open = useCallback(() => {
    setOpening(true);
    // The size is settled by the fit addon once the element exists; this is only the
    // initial grid the shell is told about.
    openTerminal(shell, 80, 24)
      .then((opened: OpenedTerminal) => {
        setTabs((current) => [
          ...current,
          {
            id: opened.terminalId,
            title: shellLabel(shell),
            shellPath: opened.shellPath,
            pid: opened.pid,
            elevated: opened.elevated,
            exited: false,
          },
        ]);
        setActive(opened.terminalId);
      })
      .catch((error: unknown) => {
        onToast({
          kind: 'error',
          message: error instanceof Error ? error.message : 'Could not open a terminal.',
        });
      })
      .finally(() => {
        setOpening(false);
      });
  }, [onToast, shell]);

  const close = useCallback((id: string) => {
    closeTerminal(id).catch(() => {
      // The tab is going away either way; a server that has already forgotten the
      // session is not something to report.
    });
    setTabs((current) => current.filter((tab) => tab.id !== id));
    setActive((current) => (current === id ? null : current));
  }, []);

  // A terminal that exits keeps its tab, so the operator can read what it printed
  // before closing it. Removing it immediately would discard the error that explains
  // why the command failed.
  useEffect(() => {
    const stop = listenTerminalExit((event) => {
      setTabs((current) =>
        current.map((tab) => (tab.id === event.terminalId ? { ...tab, exited: true } : tab)),
      );
      if (event.error !== null) {
        onToast({ kind: 'error', message: event.error });
      }
    });
    return () => {
      void stop.then((unlisten) => {
        unlisten();
      });
    };
  }, [onToast]);

  return (
    <section className="animate-fade-in flex min-h-0 flex-1 flex-col">
      <PageHeader
        title="Terminal"
        description="A real shell on the server. What you type goes to a pseudo-terminal there, and what it prints comes back unaltered."
        actions={
          <div className="flex items-end gap-2">
            <SelectField label="Shell" value={shell} onChange={setShell} options={SHELLS} />
            <Button variant="primary" icon={Plus} onClick={open} disabled={opening} className="h-9">
              {opening ? 'Opening…' : 'New terminal'}
            </Button>
          </div>
        }
      />

      {tabs.length === 0 ? (
        <EmptyState
          icon={SquareTerminal}
          title="No terminals open"
          body="Choose a shell and open one. Sessions end when you close them or when the connection to the server ends — nothing is left running on the server afterwards."
        />
      ) : (
        <>
          <div
            role="tablist"
            aria-label="Terminals"
            className="mb-3 flex flex-wrap gap-1.5 border-b border-(--color-border-subtle) pb-2"
          >
            {tabs.map((tab) => (
              <div
                key={tab.id}
                className={`flex items-center rounded-lg border transition-colors duration-150 ease-(--ease-ui) ${
                  tab.id === active
                    ? 'border-(--color-accent)/40 bg-(--color-accent-soft)'
                    : 'border-(--color-border-subtle) hover:bg-(--color-surface-overlay)'
                }`}
              >
                <button
                  type="button"
                  role="tab"
                  aria-selected={tab.id === active}
                  onClick={() => {
                    setActive(tab.id);
                  }}
                  className={`flex items-center gap-1.5 rounded-l-lg px-2.5 py-1 text-xs ${
                    tab.id === active ? 'text-(--color-accent)' : 'text-(--color-text-secondary)'
                  }`}
                >
                  <SquareTerminal aria-hidden="true" className="size-3.5" />
                  {tab.title}
                  {tab.exited && ' (ended)'}
                </button>
                <button
                  type="button"
                  aria-label={`Close ${tab.title}`}
                  onClick={() => {
                    close(tab.id);
                  }}
                  className="rounded-r-lg px-1.5 py-1 text-(--color-text-muted) transition-colors duration-150 ease-(--ease-ui) hover:text-(--color-text-primary)"
                >
                  <X aria-hidden="true" className="size-3.5" />
                </button>
              </div>
            ))}
          </div>

          {tabs.map((tab) => (
            <TerminalPane key={tab.id} tab={tab} visible={tab.id === active} onToast={onToast} />
          ))}
        </>
      )}
    </section>
  );
}

/**
 * One terminal, backed by an xterm.js instance.
 *
 * Hidden rather than unmounted when another tab is active: unmounting would destroy the
 * emulator and with it the scrollback, so switching tabs would silently discard
 * everything the shell had printed.
 */
function TerminalPane({
  tab,
  visible,
  onToast,
}: {
  readonly tab: Tab;
  readonly visible: boolean;
  readonly onToast: (toast: Toast) => void;
}): React.JSX.Element {
  const host = useRef<HTMLDivElement | null>(null);
  const terminal = useRef<Terminal | null>(null);
  const fit = useRef<FitAddon | null>(null);
  const [status, setStatus] = useState<string>('');

  useEffect(() => {
    const element = host.current;
    if (element === null) return;

    const term = new Terminal({
      convertEol: false,
      cursorBlink: true,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
      fontSize: 13,
      // Bounded: a shell can print without limit, and unbounded scrollback in a
      // long-lived window is a slow memory leak.
      scrollback: 5000,
      // Matches `--color-surface-sunken` so the emulator reads as part of the app
      // rather than as an embedded black rectangle.
      theme: { background: '#0b0e13', foreground: '#e6eaf2', cursor: '#4c7df0' },
    });
    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    term.open(element);
    fitAddon.fit();

    terminal.current = term;
    fit.current = fitAddon;

    // Keystrokes go straight to the server. `data` is already the byte sequence a
    // terminal would send, including the answers xterm.js generates for the shell's
    // own queries.
    const typed = term.onData((data) => {
      sendTerminalInput(tab.id, data).catch((error: unknown) => {
        onToast({
          kind: 'error',
          message: error instanceof Error ? error.message : 'The terminal is no longer open.',
        });
      });
    });

    const resized = term.onResize(({ cols, rows }) => {
      resizeTerminal(tab.id, cols, rows).catch(() => {
        // A resize that does not arrive is cosmetic; the session still works.
      });
    });

    const stopOutput = listenTerminalOutput((event) => {
      if (event.terminalId !== tab.id) return;
      term.write(event.data);
    });

    const onWindowResize = (): void => {
      fitAddon.fit();
    };
    window.addEventListener('resize', onWindowResize);

    return () => {
      window.removeEventListener('resize', onWindowResize);
      typed.dispose();
      resized.dispose();
      void stopOutput.then((unlisten) => {
        unlisten();
      });
      term.dispose();
      terminal.current = null;
      fit.current = null;
    };
  }, [onToast, tab.id]);

  // Re-fit when this tab becomes visible: a hidden element has no size, so a fit
  // performed while it was hidden would have computed a nonsense grid.
  useEffect(() => {
    if (visible) {
      fit.current?.fit();
      terminal.current?.focus();
    }
  }, [visible]);

  useEffect(() => {
    setStatus(tab.exited ? 'The shell exited. Close this tab when you are done reading.' : '');
  }, [tab.exited]);

  return (
    <div className={visible ? 'flex min-h-0 flex-1 flex-col' : 'hidden'}>
      <div className="mb-2 flex flex-wrap items-center gap-2 text-xs text-(--color-text-secondary)">
        <span className="font-mono select-text">{tab.shellPath}</span>
        <span className="text-(--color-text-muted)">PID {tab.pid}</span>
        {tab.elevated ? (
          <StatusBadge tone="warning">Elevated</StatusBadge>
        ) : (
          <Badge>Standard privileges</Badge>
        )}
        {tab.exited && <StatusBadge tone="danger">Ended</StatusBadge>}
      </div>

      <div
        ref={host}
        className="min-h-80 flex-1 overflow-hidden rounded-xl border border-(--color-border-subtle) bg-(--color-surface-sunken) p-2"
      />

      {status !== '' && (
        <p role="status" className="mt-1.5 text-xs text-(--color-text-secondary)">
          {status}
        </p>
      )}
    </div>
  );
}

/** The label for a shell id. */
function shellLabel(id: string): string {
  return SHELLS.find((shell) => shell.id === id)?.label ?? 'Terminal';
}
