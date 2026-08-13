import { ChevronRight } from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import {
  type DownloadProgress,
  type InstallResult,
  type UpdateStatus,
  cancelUpdateDownload,
  checkForUpdates,
  downloadUpdate,
  getUpdateStatus,
  installUpdate,
  pauseUpdateDownload,
  resumeUpdateDownload,
} from './api.js';
import {
  Button,
  ConfirmDialog,
  ErrorState,
  SkeletonRows,
  StatusBadge,
  type StatusTone,
  type Toast,
} from './ui';
import { formatBytes, formatDuration, formatRate, humanise } from './format.js';
import {
  ACTIVE_STATES,
  type PrimaryAction,
  parseReleaseNotes,
  primaryAction,
  transferControls,
} from './updates.js';

/** The status tone for an update-manager state. */
function stateTone(state: UpdateStatus['state']): StatusTone {
  switch (state) {
    case 'failed':
      return 'danger';
    case 'update_available':
    case 'ready_to_install':
    case 'waiting_for_user_confirmation':
    case 'restart_required':
      return 'warning';
    case 'checking_for_updates':
    case 'preparing_download':
    case 'downloading':
    case 'resuming':
    case 'verifying':
    case 'installing':
    case 'recovering':
      return 'busy';
    case 'no_update_available':
    case 'completed':
      return 'ready';
    case 'idle':
    case 'paused':
    case 'waiting_for_network':
      return 'idle';
  }
}

interface SpeedSample {
  readonly bytes: number;
  readonly at: number;
  readonly speed: number;
  readonly firstBytes: number;
  readonly firstAt: number;
}

export default function UpdatesPane({
  onToast,
  onStatusChange,
}: {
  readonly onToast: (toast: Toast) => void;
  readonly onStatusChange?: () => void;
}): React.JSX.Element {
  const [status, setStatus] = useState<UpdateStatus | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [manifestUrl, setManifestUrl] = useState('');
  const [busy, setBusy] = useState(false);
  const [installOpen, setInstallOpen] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [speedSample, setSpeedSample] = useState<SpeedSample | null>(null);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const refresh = useCallback((): void => {
    getUpdateStatus()
      .then((next) => {
        if (!mounted.current) return;
        setStatus(next);
        setLoadError(null);
        setManifestUrl((current) =>
          current === '' && next.manifestUrl !== null ? next.manifestUrl : current,
        );
      })
      .catch((error: unknown) => {
        if (!mounted.current) return;
        // Surfaced in place rather than as a toast: without a status there is
        // nothing else on this screen to look at.
        setLoadError(messageFrom(error));
      });
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    if (status === null || !ACTIVE_STATES.has(status.state)) return;
    const timer = setInterval(refresh, 1000);
    return () => {
      clearInterval(timer);
    };
  }, [refresh, status]);

  useEffect(() => {
    const download = status?.download;
    if (download === undefined || download === null) return;
    const now = Date.now();
    setSpeedSample((previous) => {
      if (previous === null || now <= previous.at || download.downloadedBytes < previous.bytes) {
        return {
          bytes: download.downloadedBytes,
          at: now,
          speed: 0,
          firstBytes: download.downloadedBytes,
          firstAt: now,
        };
      }
      const elapsed = (now - previous.at) / 1000;
      const speed = (download.downloadedBytes - previous.bytes) / Math.max(elapsed, 0.001);
      return { ...previous, bytes: download.downloadedBytes, at: now, speed };
    });
  }, [status?.download]);

  const averageSpeed = useMemo(() => {
    const download = status?.download;
    if (download === undefined || download === null || speedSample === null) return 0;
    const elapsed = (speedSample.at - speedSample.firstAt) / 1000;
    if (elapsed <= 0) return 0;
    return (download.downloadedBytes - speedSample.firstBytes) / elapsed;
  }, [speedSample, status?.download]);

  const etaSecs = useMemo(() => {
    const download = status?.download;
    if (
      download === undefined ||
      download === null ||
      speedSample === null ||
      speedSample.speed <= 0
    ) {
      return null;
    }
    const remaining = download.totalBytes - download.downloadedBytes;
    if (remaining <= 0) return 0;
    return Math.ceil(remaining / speedSample.speed);
  }, [speedSample, status?.download]);

  const run = useCallback(
    (action: () => Promise<UpdateStatus | InstallResult>, success?: string): void => {
      setBusy(true);
      action()
        .then((result) => {
          if (!mounted.current) return;
          if ('state' in result) {
            setStatus(result);
          } else {
            onToast({ kind: 'success', message: result.message });
            refresh();
          }
          if (success !== undefined) onToast({ kind: 'success', message: success });
          onStatusChange?.();
        })
        .catch((error: unknown) => {
          if (!mounted.current) return;
          onToast({ kind: 'error', message: messageFrom(error) });
          refresh();
        })
        .finally(() => {
          if (mounted.current) setBusy(false);
        });
    },
    [onStatusChange, onToast, refresh],
  );

  if (loadError !== null && status === null) {
    return (
      <section>
        <ErrorState
          summary="The update manager couldn’t be reached."
          detail={loadError}
          onRetry={refresh}
        />
      </section>
    );
  }

  if (status === null) {
    return (
      <section>
        <SkeletonRows rows={3} />
      </section>
    );
  }

  const action = primaryAction(status);
  const controls = transferControls(status.state);
  const notes = parseReleaseNotes(status.releaseNotes);

  const invoke = (): void => {
    switch (action.kind) {
      case 'check':
        run(() => checkForUpdates(manifestUrl.trim() === '' ? null : manifestUrl.trim()));
        break;
      case 'download':
        run(downloadUpdate);
        break;
      case 'install':
        setInstallOpen(true);
        break;
      case 'restart':
        onToast({
          kind: 'success',
          message: 'Close and reopen the application to finish the update.',
        });
        break;
      case 'none':
      case 'progress':
        // Nothing for the user to do; the button is disabled or replaced by
        // the progress panel.
        break;
    }
  };

  return (
    <section>
      <p className="mb-3 flex items-center gap-2 text-xs text-(--color-text-secondary)">
        <StatusBadge tone={stateTone(status.state)}>{humanise(status.state)}</StatusBadge>
        Verified against a signed manifest and a SHA-256 checksum. Nothing installs without your
        confirmation.
      </p>

      <div className="rounded-lg border border-(--color-border) p-4">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <p className="text-sm font-semibold">{versionHeadline(status)}</p>
            <p className="mt-1 text-sm text-(--color-text-secondary)">{action.detail}</p>
          </div>
          {action.kind !== 'progress' && (
            <Button
              variant={action.kind === 'none' ? 'ghost' : 'primary'}
              disabled={busy || action.disabled}
              onClick={invoke}
            >
              {action.label}
            </Button>
          )}
        </div>

        {status.download !== null && action.kind === 'progress' && (
          <DownloadProgressPanel
            download={status.download}
            action={action}
            speed={speedSample?.speed ?? 0}
            averageSpeed={averageSpeed}
            etaSecs={etaSecs}
          />
        )}

        {(controls.canPause || controls.canResume || controls.canCancel) && (
          <div className="mt-4 flex flex-wrap items-center gap-4 text-sm">
            {controls.canPause && (
              <LinkButton
                disabled={busy}
                onClick={() => {
                  run(pauseUpdateDownload, 'Download paused.');
                }}
              >
                Pause
              </LinkButton>
            )}
            {controls.canResume && (
              <LinkButton
                disabled={busy}
                onClick={() => {
                  run(resumeUpdateDownload);
                }}
              >
                Resume
              </LinkButton>
            )}
            {controls.canCancel && (
              <LinkButton
                danger
                disabled={busy}
                onClick={() => {
                  run(
                    () => cancelUpdateDownload(true),
                    'Download cancelled and partial files removed.',
                  );
                }}
              >
                Cancel
              </LinkButton>
            )}
          </div>
        )}
      </div>

      {status.lastError !== null && status.state === 'failed' && (
        <div className="mt-4">
          <ErrorState summary="The last update attempt failed." detail={status.lastError} />
        </div>
      )}

      {notes.length > 0 && (
        <section className="mt-6">
          <h3 className="mb-3 text-sm font-semibold">
            What&rsquo;s new
            {status.availableVersion === null ? '' : ` in ${status.availableVersion}`}
          </h3>
          {notes.map((section) => (
            <div key={section.heading} className="mb-3">
              {section.heading !== '' && (
                <p className="mb-1 text-sm font-medium">{section.heading}</p>
              )}
              {section.items.length > 0 && (
                <ul className="list-disc space-y-1 pl-5 text-sm text-(--color-text-secondary)">
                  {section.items.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              )}
            </div>
          ))}
        </section>
      )}

      <section className="mt-6 border-t border-(--color-border) pt-4">
        <button
          type="button"
          aria-expanded={advancedOpen}
          onClick={() => {
            setAdvancedOpen((open) => !open);
          }}
          className="flex items-center gap-1.5 text-sm text-(--color-text-secondary) transition-colors duration-150 ease-(--ease-ui) hover:text-(--color-text)"
        >
          <ChevronRight
            aria-hidden="true"
            className={`size-3.5 transition-transform duration-150 ease-(--ease-ui) ${advancedOpen ? 'rotate-90' : ''}`}
          />
          Advanced
        </button>

        {advancedOpen && (
          <div className="mt-3">
            <form
              className="mb-4"
              onSubmit={(event) => {
                event.preventDefault();
                run(() => checkForUpdates(manifestUrl.trim() === '' ? null : manifestUrl.trim()));
              }}
            >
              <label className="mb-1 block text-sm font-medium" htmlFor="manifest-url">
                Release metadata URL
              </label>
              <p className="mb-2 text-xs text-(--color-text-secondary)">
                Leave empty to use the release channel this build ships with.
              </p>
              <div className="flex gap-2">
                <input
                  id="manifest-url"
                  type="url"
                  value={manifestUrl}
                  onChange={(event) => {
                    setManifestUrl(event.currentTarget.value);
                  }}
                  placeholder="https://example.com/releases/release-index.json"
                  className="min-w-0 flex-1 rounded border border-(--color-border) bg-(--color-page) px-3 py-1.5 text-sm"
                />
                <Button type="submit" disabled={busy}>
                  Check
                </Button>
              </div>
            </form>

            <dl className="divide-y divide-(--color-border) rounded border border-(--color-border)">
              {(
                [
                  ['Current version', status.currentVersion],
                  ['Available version', status.availableVersion ?? 'Not checked'],
                  ['State', humanise(status.state)],
                  ['Platform', status.platform.key],
                  ['Package', status.packageFormat ?? 'Not selected'],
                ] as const
              ).map(([label, value]) => (
                <div key={label} className="flex justify-between gap-4 px-3 py-2 text-sm">
                  <dt className="text-(--color-text-secondary)">{label}</dt>
                  <dd className="font-mono">{value}</dd>
                </div>
              ))}
            </dl>
          </div>
        )}
      </section>

      <ConfirmDialog
        open={installOpen}
        title="Install update?"
        confirmLabel="Install Now"
        onCancel={() => {
          setInstallOpen(false);
        }}
        onConfirm={() => {
          setInstallOpen(false);
          run(installUpdate);
        }}
        body={
          <div className="space-y-2">
            <p>Version {status.availableVersion ?? 'unknown'} is verified and ready.</p>
            <p>
              Installation may ask for administrator privileges and may require restarting the
              application. It will not begin unless you choose Install Now.
            </p>
          </div>
        }
      />
    </section>
  );
}

function versionHeadline(status: UpdateStatus): string {
  if (status.availableVersion === null || status.availableVersion === status.currentVersion) {
    return `Version ${status.currentVersion}`;
  }
  return `${status.currentVersion} → ${status.availableVersion}`;
}

function LinkButton({
  children,
  onClick,
  disabled = false,
  danger = false,
}: {
  readonly children: React.ReactNode;
  readonly onClick: () => void;
  readonly disabled?: boolean;
  readonly danger?: boolean;
}): React.JSX.Element {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onClick}
      className={
        'underline underline-offset-2 disabled:cursor-not-allowed disabled:opacity-50 ' +
        (danger ? 'text-(--color-danger)' : 'text-(--color-text-secondary)')
      }
    >
      {children}
    </button>
  );
}

function DownloadProgressPanel({
  download,
  action,
  speed,
  averageSpeed,
  etaSecs,
}: {
  readonly download: DownloadProgress;
  readonly action: PrimaryAction;
  readonly speed: number;
  readonly averageSpeed: number;
  readonly etaSecs: number | null;
}): React.JSX.Element {
  const eta = etaSecs === null ? 'Calculating…' : `${formatDuration(etaSecs)} remaining`;
  return (
    <div className="mt-4">
      <div className="mb-2 flex items-center justify-between text-sm">
        <span className="font-medium">{action.label}</span>
        <span className="tabular-nums">{download.percent.toFixed(1)}%</span>
      </div>
      <div
        role="progressbar"
        aria-valuenow={Math.round(download.percent)}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label="Download progress"
        className="h-2 overflow-hidden rounded-full bg-(--color-page)"
      >
        <div
          className="h-full rounded-full bg-(--color-accent) transition-[width] duration-500"
          style={{ width: `${download.percent}%` }}
        />
      </div>
      <p className="mt-2 text-sm text-(--color-text-secondary)">
        {formatBytes(download.downloadedBytes)} / {formatBytes(download.totalBytes)} ·{' '}
        {formatRate(speed)} · {eta}
      </p>
      <p className="mt-1 text-xs text-(--color-text-secondary)">
        {formatRate(averageSpeed)} average · {humanise(download.state)}
        {download.retryCount > 0 && ` · retried ${download.retryCount}×`}
      </p>
    </div>
  );
}

function messageFrom(error: unknown): string {
  return error instanceof Error ? error.message : 'The update operation failed.';
}
