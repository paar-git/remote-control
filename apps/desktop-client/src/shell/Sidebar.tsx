/**
 * The primary navigation.
 *
 * Three rules hold this together:
 *
 * * **Groups are labelled.** Twelve flat items are a list; four labelled groups are a
 *   structure the operator can navigate without reading every entry.
 * * **Unavailable is a state, not an absence.** A section that is not built keeps its
 *   icon and its readable label and gains a lock, so it reads as deliberately not ready
 *   rather than as something broken.
 * * **Collapsed loses the labels, never the meaning.** Every item carries a tooltip that
 *   becomes its name once the rail is narrow.
 */

import { ChevronsLeft, ChevronsRight, Lock, MonitorCog, ShieldCheck } from 'lucide-react';

import { Kbd, StatusDot, Tooltip, type StatusTone } from '../ui';
import { NAV_GROUPS, NO_SESSION_REASON, UNAVAILABLE_REASON, type NavItem } from './navigation';

export interface ServiceStatus {
  readonly tone: StatusTone;
  readonly label: string;
  /** The longer explanation, shown on hover. */
  readonly detail: string;
}

export function Sidebar({
  section,
  onSelect,
  collapsed,
  onToggleCollapsed,
  username,
  onLock,
  updateBadge,
  service,
  sessionActive,
}: {
  readonly section: string;
  readonly onSelect: (id: string) => void;
  readonly collapsed: boolean;
  readonly onToggleCollapsed: () => void;
  readonly username: string;
  readonly onLock: () => void;
  /** The version waiting to be installed, if any. */
  readonly updateBadge: string | null;
  readonly service: ServiceStatus;
  /** Whether a session is open, which is what makes the session tools usable. */
  readonly sessionActive: boolean;
}): React.JSX.Element {
  return (
    <nav
      aria-label="Sections"
      className={`flex shrink-0 flex-col border-r border-(--color-border) bg-(--color-page) transition-[width] duration-200 ease-(--ease-ui) ${
        collapsed ? 'w-[64px]' : 'w-60'
      }`}
    >
      <SidebarHeader collapsed={collapsed} onToggleCollapsed={onToggleCollapsed} />
      <ServiceIndicator collapsed={collapsed} service={service} />

      <div className="flex-1 overflow-x-hidden overflow-y-auto px-2 pt-1 pb-4">
        {NAV_GROUPS.map((group) => (
          <SidebarSection key={group.id} label={group.label} collapsed={collapsed}>
            {group.items.map((item) => (
              <SidebarItem
                key={item.id}
                item={item}
                collapsed={collapsed}
                current={item.id === section}
                badge={item.id === 'updates' ? updateBadge : null}
                sessionActive={sessionActive}
                onSelect={() => {
                  onSelect(item.id);
                }}
              />
            ))}
          </SidebarSection>
        ))}
      </div>

      <SidebarFooter collapsed={collapsed} username={username} onLock={onLock} />
    </nav>
  );
}

/** The branded header: product mark, name, and the collapse control. */
function SidebarHeader({
  collapsed,
  onToggleCollapsed,
}: {
  readonly collapsed: boolean;
  readonly onToggleCollapsed: () => void;
}): React.JSX.Element {
  return (
    <div
      className={`flex h-14 shrink-0 items-center gap-2.5 border-b border-(--color-border) ${
        collapsed ? 'justify-center px-2' : 'px-3'
      }`}
    >
      {!collapsed && (
        <>
          <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-(--color-accent) text-(--color-accent-text)">
            <MonitorCog aria-hidden="true" className="size-4.5" />
          </span>
          <span className="min-w-0 flex-1">
            <span className="block truncate text-sm font-semibold tracking-[-0.01em]">
              Remote Control
            </span>
            <span className="block truncate text-[11px] text-(--color-text-secondary)">
              Secure device access
            </span>
          </span>
        </>
      )}
      <Tooltip label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'} side="right">
        <button
          type="button"
          onClick={onToggleCollapsed}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          aria-expanded={!collapsed}
          className="flex size-8 shrink-0 items-center justify-center rounded-lg text-(--color-text-secondary) transition-colors duration-150 ease-(--ease-ui) hover:bg-(--color-hover) hover:text-(--color-text)"
        >
          {collapsed ? (
            <ChevronsRight aria-hidden="true" className="size-4" />
          ) : (
            <ChevronsLeft aria-hidden="true" className="size-4" />
          )}
        </button>
      </Tooltip>
    </div>
  );
}

/** Whether this installation is ready to work, in one line. */
function ServiceIndicator({
  collapsed,
  service,
}: {
  readonly collapsed: boolean;
  readonly service: ServiceStatus;
}): React.JSX.Element {
  if (collapsed) {
    return (
      <div className="flex justify-center py-3">
        <Tooltip label={`${service.label} — ${service.detail}`} side="right">
          <span className="flex size-8 items-center justify-center rounded-lg">
            <StatusDot tone={service.tone} />
          </span>
        </Tooltip>
      </div>
    );
  }

  return (
    <div className="px-3 py-3">
      <Tooltip label={service.detail} side="right">
        <span className="flex w-full items-center gap-2 rounded-lg border border-(--color-border) bg-(--color-page)/60 px-2.5 py-1.5">
          <StatusDot tone={service.tone} />
          <span className="min-w-0 truncate text-xs text-(--color-text-secondary)">
            {service.label}
          </span>
        </span>
      </Tooltip>
    </div>
  );
}

/** A labelled group of navigation items. */
export function SidebarSection({
  label,
  collapsed,
  children,
}: {
  readonly label: string;
  readonly collapsed: boolean;
  readonly children: React.ReactNode;
}): React.JSX.Element {
  return (
    <div className="mb-4 last:mb-0">
      {collapsed ? (
        // A rule instead of a heading: the separation survives, the text does not fit.
        <div aria-hidden="true" className="mx-2 mb-2 border-t border-(--color-border)" />
      ) : (
        <h2 className="mb-1 px-2.5 text-[10px] font-semibold tracking-[0.08em] text-(--color-text-secondary) uppercase">
          {label}
        </h2>
      )}
      <ul className="flex flex-col gap-px">{children}</ul>
    </div>
  );
}

/** One navigation item, in either its available or its unavailable form. */
export function SidebarItem({
  item,
  collapsed,
  current,
  badge,
  sessionActive,
  onSelect,
}: {
  readonly item: NavItem;
  readonly collapsed: boolean;
  readonly current: boolean;
  readonly badge: string | null;
  readonly sessionActive: boolean;
  readonly onSelect: () => void;
}): React.JSX.Element {
  const available = item.availableInPhase === null;
  const Icon = item.icon;

  // A session tool with no session is still reachable — the screen it opens explains
  // itself far better than a disabled button does — but it is dimmed, and it says why
  // on hover, so the operator is not surprised by what they find.
  const idle = available && item.needsSession === true && !sessionActive;

  const tooltip = !available
    ? `${item.label} — ${UNAVAILABLE_REASON}`
    : idle
      ? `${item.label} — ${NO_SESSION_REASON}`
      : collapsed
        ? `${item.label}${item.shortcut === undefined ? '' : ` · ${item.shortcut}`}`
        : item.description;

  return (
    <li>
      <Tooltip label={tooltip} side="right">
        <button
          type="button"
          disabled={!available}
          aria-current={current ? 'page' : undefined}
          onClick={onSelect}
          className={
            'relative flex h-8 w-full items-center rounded-lg text-sm transition-[background-color,color] duration-150 ease-(--ease-ui) ' +
            (collapsed ? 'justify-center px-0 ' : 'gap-2.5 px-2.5 ') +
            (!available
              ? 'cursor-not-allowed text-(--color-text-secondary) '
              : current
                ? 'bg-(--color-accent-soft) font-medium text-(--color-text) '
                : idle
                  ? 'text-(--color-text-secondary) hover:bg-(--color-hover) hover:text-(--color-text-secondary) '
                  : 'text-(--color-text-secondary) hover:bg-(--color-hover) hover:text-(--color-text) ')
          }
        >
          {/* The active marker. Absolutely positioned so it never shifts the row. */}
          {current && (
            <span
              aria-hidden="true"
              className="absolute top-1.5 bottom-1.5 -left-2 w-0.5 rounded-r bg-(--color-accent)"
            />
          )}

          <span className="relative flex shrink-0 items-center">
            <Icon
              aria-hidden="true"
              className={`size-4 ${current ? 'text-(--color-accent)' : ''}`}
            />
            {/* Collapsed, the row has no room for a badge, so the icon carries it. */}
            {collapsed && badge !== null && (
              <span className="absolute -top-0.5 -right-0.5 size-1.5 rounded-full bg-(--color-accent) ring-2 ring-(--color-page)" />
            )}
          </span>

          {!collapsed && (
            <>
              <span className="min-w-0 flex-1 truncate text-left">{item.label}</span>
              {badge !== null && (
                <span
                  aria-label={`Version ${badge} available`}
                  className="rounded-full bg-(--color-accent) px-1.5 py-px text-[10px] font-semibold text-(--color-accent-text)"
                >
                  New
                </span>
              )}
              {available && badge === null && item.shortcut !== undefined && (
                <Kbd>{item.shortcut.replace('Ctrl+', 'Ctrl ')}</Kbd>
              )}
              {!available && (
                <span className="flex items-center gap-1 text-[10px] text-(--color-text-secondary)">
                  <Lock aria-hidden="true" className="size-3" />
                  Soon
                </span>
              )}
            </>
          )}
        </button>
      </Tooltip>
    </li>
  );
}

/** The account and session-security block. */
function SidebarFooter({
  collapsed,
  username,
  onLock,
}: {
  readonly collapsed: boolean;
  readonly username: string;
  readonly onLock: () => void;
}): React.JSX.Element {
  const initial = username.trim().slice(0, 1).toUpperCase() || '?';

  if (collapsed) {
    return (
      <div className="flex flex-col items-center gap-1.5 border-t border-(--color-border) p-2">
        <Tooltip label={`${username} · Local owner`} side="right">
          <span className="flex size-8 items-center justify-center rounded-full bg-(--color-accent-soft) text-xs font-semibold text-(--color-accent)">
            {initial}
          </span>
        </Tooltip>
        <Tooltip label="Lock session" side="right">
          <button
            type="button"
            onClick={onLock}
            aria-label="Lock session"
            className="flex size-8 items-center justify-center rounded-lg text-(--color-text-secondary) transition-colors duration-150 ease-(--ease-ui) hover:bg-(--color-hover) hover:text-(--color-text)"
          >
            <Lock aria-hidden="true" className="size-4" />
          </button>
        </Tooltip>
      </div>
    );
  }

  return (
    <div className="border-t border-(--color-border) p-2">
      <div className="flex items-center gap-2.5 rounded-lg px-1.5 py-1.5">
        <span className="flex size-8 shrink-0 items-center justify-center rounded-full bg-(--color-accent-soft) text-xs font-semibold text-(--color-accent)">
          {initial}
        </span>
        <span className="min-w-0 flex-1">
          <span className="block truncate text-sm font-medium">{username}</span>
          <span className="flex items-center gap-1 text-[11px] text-(--color-text-secondary)">
            <ShieldCheck aria-hidden="true" className="size-3" />
            Local owner
          </span>
        </span>
      </div>
      <button
        type="button"
        onClick={onLock}
        className="mt-1 flex h-8 w-full items-center gap-2.5 rounded-lg px-2.5 text-sm text-(--color-text-secondary) transition-colors duration-150 ease-(--ease-ui) hover:bg-(--color-hover) hover:text-(--color-text)"
      >
        <Lock aria-hidden="true" className="size-4 shrink-0" />
        Lock session
      </button>
    </div>
  );
}
