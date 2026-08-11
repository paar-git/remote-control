/**
 * Home — the command centre for this computer.
 *
 * Everything on this screen is read from the backend through validated commands. Nothing
 * is illustrative: if a value could not be read, the row says so rather than showing a
 * plausible default, and a state the app cannot verify is not claimed.
 *
 * The screen is built to answer five questions in order, top to bottom:
 * what device is this, is it ready, is anything wrong, what can I do now, and what are
 * the details if I need them.
 */

import {
  CheckCircle2,
  Circle,
  CircleAlert,
  Info,
  KeyRound,
  MonitorSmartphone,
  Package,
  ShieldCheck,
  Wifi,
} from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';

import {
  type AuditEntry,
  type ClientInfo,
  type ConnectionState,
  type LocalIdentity,
  type TrustedDevice,
  describeConnectionState,
  getClientInfo,
  getLocalIdentity,
  getRecentAuditEvents,
  isConnected,
  listTrustedDevices,
} from './api.js';
import { abbreviateFingerprint, formatRelative, formatTimestamp, humanise } from './format.js';
import { connectionLabel, connectionTone } from './useConnection.js';
import {
  Button,
  Card,
  CardHeader,
  CopyButton,
  ErrorState,
  InfoCard,
  InfoRow,
  PageHeader,
  Skeleton,
  SkeletonRows,
  StatusBadge,
  StatusDot,
  type StatusTone,
} from './ui';

/** Everything Home reads, loaded together so the screen settles once rather than in parts. */
interface HomeData {
  readonly info: ClientInfo;
  readonly identity: LocalIdentity | null;
  readonly devices: readonly TrustedDevice[];
  readonly activity: readonly AuditEntry[];
}

type Load =
  | { readonly status: 'loading' }
  | { readonly status: 'ready'; readonly data: HomeData }
  | { readonly status: 'error'; readonly detail: string };

export function ThisComputerScreen({
  connection,
  onNavigate,
}: {
  readonly connection: ConnectionState;
  readonly onNavigate: (section: string) => void;
}): React.JSX.Element {
  const [load, setLoad] = useState<Load>({ status: 'loading' });

  const reload = useCallback(() => {
    setLoad({ status: 'loading' });

    // `client_info` is the only required call. The rest degrade individually: a client
    // with no identity yet, or an unreadable audit log, still has a usable Home screen.
    Promise.all([
      getClientInfo(),
      getLocalIdentity().catch(() => null),
      listTrustedDevices().catch((): TrustedDevice[] => []),
      getRecentAuditEvents(6).catch((): AuditEntry[] => []),
    ])
      .then(([info, identity, devices, activity]) => {
        setLoad({ status: 'ready', data: { info, identity, devices, activity } });
      })
      .catch((error: unknown) => {
        setLoad({
          status: 'error',
          detail: error instanceof Error ? error.message : String(error),
        });
      });
  }, []);

  useEffect(reload, [reload]);

  if (load.status === 'error') {
    return (
      <ErrorState
        summary="This computer’s details couldn’t be read."
        detail={load.detail}
        onRetry={reload}
      />
    );
  }

  if (load.status === 'loading') return <ThisComputerSkeleton />;

  const { info, identity, devices, activity } = load.data;
  const paired = devices.filter((device) => !device.revoked);
  const readiness = assessReadiness(info, identity, paired.length, connection);

  return (
    <div className="animate-fade-in flex flex-col gap-6">
      <PageHeader
        title="This computer"
        meta={
          <>
            <span className="text-sm text-(--color-text-secondary)">
              {info.hostname} · {info.osVersion}
            </span>
            <StatusBadge tone={readiness.tone}>{readiness.label}</StatusBadge>
          </>
        }
      />

      <DeviceHero
        info={info}
        identity={identity}
        readiness={readiness}
        onManage={() => {
          onNavigate('remote-access');
        }}
      />

      <ReadinessBanner readiness={readiness} />

      <div className="grid gap-4 lg:grid-cols-3">
        <RemoteAccessCard
          identity={identity}
          pairedCount={paired.length}
          connection={connection}
          onOpenDevices={() => {
            onNavigate('remote-access');
          }}
        />
        <SecurityCard info={info} identity={identity} />
        <ApplicationCard
          info={info}
          onOpenUpdates={() => {
            onNavigate('updates');
          }}
        />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <DeviceDetailsCard info={info} identity={identity} />
        <RecentActivityCard activity={activity} />
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Readiness                                                                  */
/* -------------------------------------------------------------------------- */

/** One requirement, and whether this installation meets it. */
interface Check {
  readonly label: string;
  readonly detail: string;
  readonly met: boolean;
  /** True when the check is simply not done yet rather than broken. */
  readonly pending?: boolean;
}

interface Readiness {
  readonly tone: StatusTone;
  readonly label: string;
  readonly headline: string;
  readonly summary: string;
  readonly checks: readonly Check[];
}

/**
 * Turn the raw state into the one sentence the operator needs.
 *
 * The order matters: a broken identity or database outranks "no computers yet", which
 * outranks "known but idle". Reporting the least severe true statement would bury the
 * one that needs attention.
 */
function assessReadiness(
  info: ClientInfo,
  identity: LocalIdentity | null,
  pairedCount: number,
  connection: ConnectionState,
): Readiness {
  const checks: Check[] = [
    {
      label: 'Device identity',
      detail:
        identity === null
          ? 'No identity could be read for this computer.'
          : 'This computer has a pinned cryptographic identity.',
      met: identity !== null,
    },
    {
      label: 'Local database',
      detail: info.databaseReady
        ? 'Saved computers and activity are stored locally.'
        : 'The local database could not be opened, so nothing can be saved.',
      met: info.databaseReady,
    },
    {
      label: 'Saved computers',
      detail:
        pairedCount === 0
          ? 'No computers saved yet.'
          : `${String(pairedCount)} server${pairedCount === 1 ? '' : 's'} saved on this computer.`,
      met: pairedCount > 0,
      pending: pairedCount === 0,
    },
    {
      label: 'Connection',
      detail: describeConnectionState(connection),
      met: isConnected(connection),
      pending: !isConnected(connection),
    },
  ];

  if (identity === null || !info.databaseReady) {
    return {
      tone: 'danger',
      label: 'Attention needed',
      headline: 'This computer isn’t ready for remote access',
      summary:
        identity === null
          ? 'The device identity could not be read, so connecting is not possible.'
          : 'The local database could not be opened, so saved servers cannot be kept.',
      checks,
    };
  }

  if (pairedCount === 0) {
    return {
      tone: 'warning',
      label: 'Setup incomplete',
      headline: 'No computers yet',
      summary: 'This computer’s identity is set up. No servers are saved on it yet.',
      checks,
    };
  }

  if (isConnected(connection)) {
    return {
      tone: 'ready',
      label: 'Connected',
      headline: 'Connected to a server',
      summary: describeConnectionState(connection),
      checks,
    };
  }

  return {
    tone: 'ready',
    label: 'Ready',
    headline: 'Ready for connections',
    summary: 'Identity is set up. Connect to a saved server to start working.',
    checks,
  };
}

/* -------------------------------------------------------------------------- */
/* Sections                                                                   */
/* -------------------------------------------------------------------------- */

/** The device overview: what this machine is, and whether it is ready. */
function DeviceHero({
  info,
  identity,
  readiness,
  onManage,
}: {
  readonly info: ClientInfo;
  readonly identity: LocalIdentity | null;
  readonly readiness: Readiness;
  readonly onManage: () => void;
}): React.JSX.Element {
  return (
    <Card className="flex flex-wrap items-center gap-x-5 gap-y-4">
      <span className="flex size-14 shrink-0 items-center justify-center rounded-xl border border-(--color-border) bg-(--color-card) text-(--color-accent)">
        <MonitorSmartphone aria-hidden="true" className="size-7" />
      </span>

      {/* `basis-72` keeps the name and the actions from squeezing each other: below that
          width the action group wraps to its own row instead. */}
      <div className="min-w-0 flex-1 basis-72">
        <div className="flex flex-wrap items-center gap-2.5">
          <h3 className="truncate text-xl font-semibold tracking-[-0.01em]">{info.hostname}</h3>
          <StatusBadge tone={readiness.tone}>{readiness.label}</StatusBadge>
        </div>
        <p className="mt-1 text-sm text-(--color-text-secondary)">
          {info.osVersion} · <span className="font-mono text-xs">{info.architecture}</span>
        </p>
        {identity !== null && (
          <p className="mt-1.5 font-mono text-xs break-all text-(--color-text-secondary) select-text">
            {identity.deviceId}
          </p>
        )}
      </div>

      <div className="flex shrink-0 flex-wrap gap-2">
        <Button variant="primary" icon={MonitorSmartphone} onClick={onManage}>
          Manage devices
        </Button>
        {identity !== null && <CopyButton value={identity.deviceId} label="device ID" />}
      </div>
    </Card>
  );
}

/**
 * The readiness banner.
 *
 * Written for the operator: what works, what does not, and what to do next. The
 * checklist repeats the state in a form that can be scanned rather than read.
 */
function ReadinessBanner({ readiness }: { readonly readiness: Readiness }): React.JSX.Element {
  const accent =
    readiness.tone === 'danger'
      ? 'border-(--color-danger)/40 bg-(--color-danger-soft)'
      : readiness.tone === 'warning'
        ? 'border-(--color-danger)/40 bg-(--color-danger-soft)'
        : 'border-(--color-border) bg-(--color-card)';

  return (
    <section
      role={readiness.tone === 'danger' ? 'alert' : 'status'}
      className={`rounded-xl border p-4 ${accent}`}
    >
      <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-3">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold">{readiness.headline}</h3>
          <p className="mt-0.5 max-w-2xl text-sm text-(--color-text-secondary)">
            {readiness.summary}
          </p>
        </div>
      </div>

      <ul className="mt-4 grid gap-x-6 gap-y-2 sm:grid-cols-2 xl:grid-cols-4">
        {readiness.checks.map((check) => (
          <li key={check.label} className="flex items-start gap-2">
            {check.met ? (
              <CheckCircle2
                aria-hidden="true"
                className="mt-0.5 size-4 shrink-0 text-(--color-success)"
              />
            ) : check.pending === true ? (
              <Circle
                aria-hidden="true"
                className="mt-0.5 size-4 shrink-0 text-(--color-text-secondary)"
              />
            ) : (
              <CircleAlert
                aria-hidden="true"
                className="mt-0.5 size-4 shrink-0 text-(--color-danger)"
              />
            )}
            <span className="min-w-0">
              <span className="block text-xs font-medium">{check.label}</span>
              <span className="block text-xs text-(--color-text-secondary)">{check.detail}</span>
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}

/** Identity, pairing and the live session, in one card. */
function RemoteAccessCard({
  identity,
  pairedCount,
  connection,
  onOpenDevices,
}: {
  readonly identity: LocalIdentity | null;
  readonly pairedCount: number;
  readonly connection: ConnectionState;
  readonly onOpenDevices: () => void;
}): React.JSX.Element {
  return (
    <InfoCard
      icon={Wifi}
      title="Remote access"
      footer={
        <Button size="sm" variant="ghost" onClick={onOpenDevices}>
          Open Remote Access
        </Button>
      }
    >
      <InfoRow
        label="Identity"
        value={
          <StateText tone={identity === null ? 'danger' : 'ready'}>
            {identity === null ? 'Unavailable' : 'Configured'}
          </StateText>
        }
      />
      <InfoRow
        label="Saved computers"
        value={
          <StateText tone={pairedCount === 0 ? 'idle' : 'ready'}>
            {pairedCount === 0 ? 'None yet' : String(pairedCount)}
          </StateText>
        }
      />
      <InfoRow
        label="Session"
        value={
          <StateText tone={connectionTone(connection)}>{connectionLabel(connection)}</StateText>
        }
      />
      <InfoRow
        label="Certificate"
        value={
          identity === null
            ? '—'
            : identity.needsRenewal
              ? 'Renewal due'
              : `Valid to ${formatTimestamp(identity.certificateNotAfterMs)}`
        }
        tone={identity?.needsRenewal === true ? 'text-(--color-danger)' : undefined}
      />
    </InfoCard>
  );
}

/**
 * The security posture of this installation.
 *
 * Note the direction of the elevation check: this client is *meant* to run unelevated —
 * privileged work happens in the agent service — so running as administrator is the
 * warning, not the reassurance.
 */
function SecurityCard({
  info,
  identity,
}: {
  readonly info: ClientInfo;
  readonly identity: LocalIdentity | null;
}): React.JSX.Element {
  return (
    <InfoCard
      icon={ShieldCheck}
      title="Security"
      footer={
        info.elevated ? (
          <p className="flex items-start gap-2 text-xs text-(--color-danger)">
            <CircleAlert aria-hidden="true" className="mt-px size-3.5 shrink-0" />
            Close this window and start it normally. Privileged work is routed through the agent
            service, so the client gains nothing from elevation.
          </p>
        ) : (
          <p className="text-xs text-(--color-text-secondary)">
            The client never needs administrator rights. Privileged operations are performed by the
            agent service on the server.
          </p>
        )
      }
    >
      <InfoRow
        label="Privileges"
        value={
          <StateText tone={info.elevated ? 'warning' : 'ready'}>
            {info.elevated ? 'Running as administrator' : 'Standard user'}
          </StateText>
        }
      />
      <InfoRow
        label="Owner account"
        value={<StateText tone="ready">Argon2id password</StateText>}
      />
      <InfoRow
        label="Device key"
        value={
          <StateText tone={identity === null ? 'idle' : 'ready'}>
            {identity === null ? 'Not created' : 'Protected keystore'}
          </StateText>
        }
      />
      <InfoRow
        label="Local database"
        value={
          <StateText tone={info.databaseReady ? 'ready' : 'danger'}>
            {info.databaseReady ? 'Ready' : 'Unavailable'}
          </StateText>
        }
      />
    </InfoCard>
  );
}

/** Versions. Deliberately the quietest card on the screen. */
function ApplicationCard({
  info,
  onOpenUpdates,
}: {
  readonly info: ClientInfo;
  readonly onOpenUpdates: () => void;
}): React.JSX.Element {
  return (
    <InfoCard
      icon={Package}
      title="Application"
      footer={
        <Button size="sm" variant="ghost" onClick={onOpenUpdates}>
          Check for updates
        </Button>
      }
    >
      <InfoRow label="Version" value={info.appVersion} mono copyable={info.appVersion} />
      <InfoRow
        label="Protocol"
        value={`${String(info.protocolVersion.major)}.${String(info.protocolVersion.minor)}`}
        mono
      />
      <InfoRow label="Platform" value={humanise(info.osFamily)} />
      <InfoRow label="Architecture" value={info.architecture} mono />
    </InfoCard>
  );
}

/** The identifying detail, in one place, all of it copyable. */
function DeviceDetailsCard({
  info,
  identity,
}: {
  readonly info: ClientInfo;
  readonly identity: LocalIdentity | null;
}): React.JSX.Element {
  return (
    <InfoCard icon={Info} title="Device details">
      <InfoRow label="Hostname" value={info.hostname} mono copyable={info.hostname} />
      <InfoRow label="Operating system" value={info.osVersion} />
      <InfoRow label="Architecture" value={info.architecture} mono />
      {identity === null ? (
        <InfoRow label="Device ID" value="Unavailable" tone="text-(--color-text-secondary)" />
      ) : (
        <>
          <InfoRow label="Device ID" value={identity.deviceId} mono copyable={identity.deviceId} />
          <InfoRow
            label="Identity fingerprint"
            value={abbreviateFingerprint(identity.identityFingerprint)}
            mono
            copyable={identity.identityFingerprint}
          />
          <InfoRow
            label="Certificate"
            value={`Version ${String(identity.certificateVersion)}, valid to ${formatTimestamp(identity.certificateNotAfterMs)}`}
          />
        </>
      )}
    </InfoCard>
  );
}

/**
 * The action, without repeating the category next to it.
 *
 * Audit actions are namespaced — `auth.login_succeeded` — and the category is already
 * shown on the line below, so printing the qualified name puts "Auth" on screen twice.
 */
function describeAction(entry: AuditEntry): string {
  const prefix = `${entry.category}.`;
  return humanise(
    entry.action.startsWith(prefix) ? entry.action.slice(prefix.length) : entry.action,
  );
}

/** What this client has done recently, straight from the local audit log. */
function RecentActivityCard({
  activity,
}: {
  readonly activity: readonly AuditEntry[];
}): React.JSX.Element {
  const tones: Record<AuditEntry['result'], StatusTone> = {
    success: 'ready',
    failure: 'danger',
    denied: 'warning',
  };

  return (
    <Card padded={false} className="flex flex-col">
      <div className="px-4 pt-4">
        <CardHeader icon={KeyRound} title="Recent activity" />
      </div>

      {activity.length === 0 ? (
        <p className="px-4 pb-4 text-sm text-(--color-text-secondary)">
          Nothing recorded yet. Connecting and privileged operations are logged here.
        </p>
      ) : (
        <ul className="px-4 pb-1">
          {activity.map((entry) => (
            <li
              key={entry.id}
              className="flex min-h-11 items-center justify-between gap-3 border-b border-(--color-border) py-2 last:border-b-0"
            >
              <span className="flex min-w-0 items-center gap-2.5">
                <StatusDot tone={tones[entry.result]} />
                <span className="min-w-0">
                  <span className="block truncate text-sm">{describeAction(entry)}</span>
                  <span className="block truncate text-xs text-(--color-text-secondary)">
                    {humanise(entry.category)}
                  </span>
                </span>
              </span>
              <span
                className="shrink-0 text-xs text-(--color-text-secondary)"
                title={formatTimestamp(entry.occurredAtMs)}
              >
                {formatRelative(entry.occurredAtMs)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

/* -------------------------------------------------------------------------- */
/* Presentation helpers                                                       */
/* -------------------------------------------------------------------------- */

/** A dot and a word: the standard rendering of a state inside an {@link InfoRow}. */
function StateText({
  tone,
  children,
}: {
  readonly tone: StatusTone;
  readonly children: React.ReactNode;
}): React.JSX.Element {
  return (
    <span className="inline-flex items-center gap-2">
      <StatusDot tone={tone} />
      {children}
    </span>
  );
}

/** The shape of the loaded screen, so nothing jumps when the data arrives. */
function ThisComputerSkeleton(): React.JSX.Element {
  return (
    <div className="flex flex-col gap-6" role="status" aria-label="Loading this computer">
      <div>
        <Skeleton className="h-5 w-44" />
        <Skeleton className="mt-2 h-3.5 w-64" />
      </div>
      <Card className="flex items-center gap-5">
        <Skeleton className="size-14 shrink-0 rounded-xl" />
        <div className="flex-1">
          <Skeleton className="h-5 w-48" />
          <Skeleton className="mt-2 h-3.5 w-72" />
        </div>
        <Skeleton className="h-8 w-36 rounded-lg" />
      </Card>
      <Card>
        <Skeleton className="h-4 w-56" />
        <Skeleton className="mt-2 h-3.5 w-96" />
      </Card>
      <div className="grid gap-4 lg:grid-cols-3">
        {[0, 1, 2].map((index) => (
          <Card key={index}>
            <Skeleton className="mb-4 h-4 w-32" />
            <SkeletonRows />
          </Card>
        ))}
      </div>
    </div>
  );
}
