/**
 * Background update watcher for the app shell.
 *
 * Checks quietly on start-up and on a long interval so a new release surfaces
 * without the user going to look for it. Failures are deliberately silent: a
 * laptop that is offline at start-up must not greet its owner with an error.
 */

import { useCallback, useEffect, useRef, useState } from 'react';

import { type UpdateStatus, checkForUpdates, getUpdateStatus } from './api.js';
import { AUTO_CHECK_INTERVAL_MS, canAutoCheck } from './updates.js';

export interface UpdateWatcher {
  readonly status: UpdateStatus | null;
  /** Re-read the backend status, e.g. after the update screen acts. */
  readonly refresh: () => void;
}

export function useUpdateWatcher(enabled: boolean): UpdateWatcher {
  const [status, setStatus] = useState<UpdateStatus | null>(null);
  // Guards against overlapping checks when a slow request outlives its interval.
  const checking = useRef(false);
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
        if (mounted.current) setStatus(next);
      })
      .catch(() => {
        // The status call failing is not worth interrupting the user for.
      });
  }, []);

  useEffect(() => {
    if (!enabled) return;

    const check = (): void => {
      if (checking.current) return;
      checking.current = true;
      getUpdateStatus()
        .then((current) => {
          if (mounted.current) setStatus(current);
          // Checking while a download or install is running is refused by the
          // backend, so the watcher waits for the next tick instead.
          if (!canAutoCheck(current.state)) return null;
          return checkForUpdates(null);
        })
        .then((next) => {
          if (next !== null && mounted.current) setStatus(next);
        })
        .catch(() => {
          // Offline, unreachable release host, or a check refused because the
          // user started one first. All are expected and stay silent.
        })
        .finally(() => {
          checking.current = false;
        });
    };

    check();
    const timer = setInterval(check, AUTO_CHECK_INTERVAL_MS);
    return () => {
      clearInterval(timer);
    };
  }, [enabled]);

  return { status, refresh };
}
