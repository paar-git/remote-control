/**
 * Outbound address row: label, input with history, split Connect, app menu.
 */

import { ChevronDown, Menu } from 'lucide-react';
import { useEffect, useId, useRef, useState } from 'react';

import type { Recent } from '../api.js';
import { describeConnectionState, type ConnectionState } from '../api.js';
import type { View } from '../navigation.js';
import { ConfirmDialog, TextField } from '../ui';
import { SplitButton, SplitMenuItem } from './SplitButton';

export function ConnectionBar({
  address,
  onAddressChange,
  onSubmit,
  parseError,
  busy,
  failed,
  connection,
  recent,
  inputRef,
  onPickRecent,
  onConnectWithPassword,
  onNavigate,
}: {
  readonly address: string;
  readonly onAddressChange: (value: string) => void;
  readonly onSubmit: () => void;
  readonly parseError: string | null;
  readonly busy: boolean;
  readonly failed: boolean;
  readonly connection: ConnectionState;
  readonly recent: readonly Recent[];
  readonly inputRef: React.RefObject<HTMLInputElement | null>;
  readonly onPickRecent: (target: string) => void;
  readonly onConnectWithPassword: (password: string) => void;
  readonly onNavigate: (view: View) => void;
}): React.JSX.Element {
  const fieldId = useId();
  const errorId = `${fieldId}-error`;
  const [historyOpen, setHistoryOpen] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [passwordOpen, setPasswordOpen] = useState(false);
  const [password, setPassword] = useState('');
  const historyRoot = useRef<HTMLDivElement>(null);
  const menuRoot = useRef<HTMLDivElement>(null);
  const invalid = parseError !== null && parseError !== '';

  useEffect(() => {
    if (!historyOpen && !menuOpen) return;
    const onPointer = (event: PointerEvent): void => {
      const target = event.target as Node;
      if (historyRoot.current !== null && !historyRoot.current.contains(target)) {
        setHistoryOpen(false);
      }
      if (menuRoot.current !== null && !menuRoot.current.contains(target)) {
        setMenuOpen(false);
      }
    };
    window.addEventListener('pointerdown', onPointer);
    return () => {
      window.removeEventListener('pointerdown', onPointer);
    };
  }, [historyOpen, menuOpen]);

  return (
    <section className="shrink-0 border-b border-(--color-border) bg-(--color-chrome)">
      <div className="relative">
      <form
        className="rc-content flex flex-wrap items-center gap-x-6 gap-y-3 py-[29px] pr-10"
        onSubmit={(event) => {
          event.preventDefault();
          onSubmit();
        }}
      >
        <label
          htmlFor={fieldId}
          className="w-[185px] shrink-0 text-[15px] text-(--color-text-secondary)"
        >
          Enter remote address
        </label>

        <div ref={historyRoot} className="relative min-w-[240px] flex-1">
          <div
            className={
              'flex h-12 overflow-hidden rounded-[4px] border bg-(--color-input) focus-within:border-(--color-accent) ' +
              (invalid ? 'border-(--color-danger)' : 'border-(--color-border-hover)')
            }
          >
            <input
              ref={inputRef}
              id={fieldId}
              value={address}
              onChange={(event) => {
                onAddressChange(event.target.value);
              }}
              placeholder="Enter hostname or IP address"
              autoComplete="off"
              spellCheck={false}
              aria-invalid={invalid || undefined}
              aria-describedby={invalid ? errorId : undefined}
              className="h-full min-w-0 flex-1 bg-transparent px-4 text-[14px] text-(--color-text) placeholder:text-(--color-text-muted) focus:outline-none"
            />
            <button
              type="button"
              aria-label="Connection history"
              aria-expanded={historyOpen}
              onClick={() => {
                setHistoryOpen((open) => !open);
              }}
              className="flex w-12 shrink-0 items-center justify-center border-l border-(--color-border) text-(--color-text-muted) hover:bg-(--color-hover) hover:text-(--color-text)"
            >
              <ChevronDown className="size-4" />
            </button>
          </div>
          {historyOpen && (
            <div
              role="listbox"
              aria-label="Connection history"
              className="absolute inset-x-0 top-[calc(100%+4px)] z-30 rounded-[4px] border border-(--color-border) bg-(--color-card) py-1"
            >
              {recent.length === 0 ? (
                <p className="px-3 py-2 text-[13px] text-(--color-text-muted)">No recent addresses.</p>
              ) : (
                recent.slice(0, 8).map((entry) => (
                  <button
                    key={entry.address}
                    type="button"
                    role="option"
                    onClick={() => {
                      onAddressChange(entry.address);
                      setHistoryOpen(false);
                    }}
                    className="flex w-full flex-col items-start px-3 py-2 text-left hover:bg-(--color-hover)"
                  >
                    <span className="text-[13px] font-medium">{entry.machineName}</span>
                    <span className="font-mono text-[12px] text-(--color-text-muted)">
                      {entry.address}
                    </span>
                  </button>
                ))
              )}
            </div>
          )}
        </div>

        <SplitButton
          label="Connect"
          onClick={onSubmit}
          disabled={busy}
          busy={busy}
          menu={
            <>
              <SplitMenuItem
                onClick={() => {
                  setPassword('');
                  setPasswordOpen(true);
                }}
              >
                Connect with password…
              </SplitMenuItem>
              {recent.slice(0, 5).map((entry) => (
                <SplitMenuItem
                  key={entry.address}
                  onClick={() => {
                    onPickRecent(entry.address);
                  }}
                >
                  Connect to {entry.machineName}
                </SplitMenuItem>
              ))}
            </>
          }
        />

      </form>
      <div ref={menuRoot} className="absolute top-1/2 right-[25px] -translate-y-1/2">
        <button
          type="button"
          aria-label="Application menu"
          aria-expanded={menuOpen}
          onClick={() => {
            setMenuOpen((open) => !open);
          }}
          className="flex size-[22px] items-center justify-center text-(--color-text-secondary) hover:text-(--color-text)"
        >
          <Menu className="size-[22px]" />
        </button>
        {menuOpen && (
          <div
            role="menu"
            className="absolute top-[calc(100%+8px)] right-0 z-30 min-w-[160px] rounded-[4px] border border-(--color-border) bg-(--color-card) py-1"
          >
            <button
              type="button"
              role="menuitem"
              className="flex w-full px-3 py-2 text-left text-[13px] hover:bg-(--color-hover)"
              onClick={() => {
                setMenuOpen(false);
                onNavigate('settings');
              }}
            >
              Settings
            </button>
            <button
              type="button"
              role="menuitem"
              className="flex w-full px-3 py-2 text-left text-[13px] hover:bg-(--color-hover)"
              onClick={() => {
                setMenuOpen(false);
                onNavigate('sessions');
              }}
            >
              Sessions
            </button>
          </div>
        )}
      </div>
      </div>

      <ConfirmDialog
        open={passwordOpen}
        title="Unattended password"
        confirmLabel="Connect"
        onCancel={() => {
          setPasswordOpen(false);
          setPassword('');
        }}
        onConfirm={() => {
          setPasswordOpen(false);
          onConnectWithPassword(password);
          setPassword('');
        }}
        body={
          <TextField
            label="Password"
            type="password"
            value={password}
            onChange={setPassword}
            autoComplete="current-password"
            help="Sent only for this connection. It is not stored."
          />
        }
      />

      {(invalid || connection.state !== 'offline') && (
        <div className="rc-content pb-3">
          <p
            id={invalid ? errorId : undefined}
            role={failed || invalid ? 'alert' : 'status'}
            className={
              'text-[13px] ' +
              (failed || invalid ? 'text-(--color-danger)' : 'text-(--color-text-secondary)')
            }
          >
            {invalid ? parseError : describeConnectionState(connection)}
          </p>
        </div>
      )}
    </section>
  );
}
