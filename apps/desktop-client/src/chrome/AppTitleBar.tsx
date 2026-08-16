/**
 * Custom window chrome: brand, session tabs, Windows caption buttons.
 */

import { Monitor, Plus } from 'lucide-react';
import { useEffect, useState } from 'react';

import { RcMark } from './RcMark';
import {
  closeWindow,
  listenWindowMaximized,
  minimizeWindow,
  toggleMaximizeWindow,
} from './windowControls';

export function AppTitleBar({
  onNewSession,
}: {
  readonly onNewSession: () => void;
}): React.JSX.Element {
  const [maximized, setMaximized] = useState(false);

  useEffect(() => {
    let stop: (() => void) | undefined;
    void listenWindowMaximized(setMaximized).then((unlisten) => {
      stop = unlisten;
    });
    return () => {
      stop?.();
    };
  }, []);

  const toggleMaximize = (): void => {
    void toggleMaximizeWindow();
  };

  return (
    <header className="flex h-[57px] shrink-0 items-stretch border-b border-(--color-border) bg-(--color-titlebar) select-none">
      <div
        className="flex h-full w-[96px] cursor-default items-center gap-2.5 pr-2 pl-4 transition-colors duration-[120ms] hover:bg-[#1B1E21]"
        data-tauri-drag-region=""
        onDoubleClick={toggleMaximize}
      >
        <span className="pointer-events-none flex size-[21px] shrink-0 translate-y-[-0.5px] items-center justify-center">
          <RcMark size={21} />
        </span>
        <span
          className="pointer-events-none text-[15px] leading-none font-semibold tracking-[-0.03em] text-[#F3F3F3]"
          style={{
            fontFamily:
              '"Segoe UI Variable Display", "Segoe UI Variable Text", "Segoe UI", sans-serif',
          }}
        >
          RC
        </span>
      </div>

      <nav aria-label="Sessions" className="flex items-stretch">
        <span className="relative flex items-center justify-center gap-2 bg-(--color-page) px-5 text-[15px] text-(--color-text)">
          <Monitor aria-hidden="true" className="size-4" />
          Control
          <span
            aria-hidden="true"
            className="absolute inset-x-0 bottom-0 h-0.5 bg-(--color-accent)"
          />
        </span>
        <button
          type="button"
          onClick={onNewSession}
          className="flex items-center gap-2 px-5 text-[15px] text-(--color-text-secondary) transition-colors duration-125 hover:bg-(--color-hover) hover:text-(--color-text)"
        >
          <Plus aria-hidden="true" className="size-4" />
          New Session
        </button>
      </nav>

      <div className="min-w-0 flex-1" data-tauri-drag-region="" onDoubleClick={toggleMaximize} />

      <div className="flex shrink-0">
        <WindowButton label="Minimize" onClick={() => void minimizeWindow()}>
          <CaptionMinimize />
        </WindowButton>
        <WindowButton label={maximized ? 'Restore' : 'Maximize'} onClick={toggleMaximize}>
          {maximized ? <CaptionRestore /> : <CaptionMaximize />}
        </WindowButton>
        <WindowButton label="Close" onClick={() => void closeWindow()} danger>
          <CaptionClose />
        </WindowButton>
      </div>
    </header>
  );
}

function WindowButton({
  label,
  onClick,
  children,
  danger = false,
}: {
  readonly label: string;
  readonly onClick: () => void;
  readonly children: React.ReactNode;
  readonly danger?: boolean | undefined;
}): React.JSX.Element {
  return (
    <button
      type="button"
      aria-label={label}
      onClick={onClick}
      className={
        'flex w-[46px] items-center justify-center text-(--color-text-secondary) ' +
        'transition-colors duration-125 ' +
        (danger
          ? 'hover:bg-[#e81123] hover:text-white'
          : 'hover:bg-(--color-hover) hover:text-(--color-text)')
      }
    >
      {children}
    </button>
  );
}

function CaptionMinimize(): React.JSX.Element {
  return (
    <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
      <path d="M1 5h8" stroke="currentColor" strokeWidth="1" />
    </svg>
  );
}

function CaptionMaximize(): React.JSX.Element {
  return (
    <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
      <rect
        x="1.5"
        y="1.5"
        width="7"
        height="7"
        fill="none"
        stroke="currentColor"
        strokeWidth="1"
      />
    </svg>
  );
}

function CaptionRestore(): React.JSX.Element {
  return (
    <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
      <path d="M3 3h5v5" fill="none" stroke="currentColor" strokeWidth="1" />
      <rect
        x="1.5"
        y="3.5"
        width="5.5"
        height="5.5"
        fill="var(--color-titlebar)"
        stroke="currentColor"
        strokeWidth="1"
      />
    </svg>
  );
}

function CaptionClose(): React.JSX.Element {
  return (
    <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
      <path d="M2 2l6 6M8 2L2 8" stroke="currentColor" strokeWidth="1" />
    </svg>
  );
}
