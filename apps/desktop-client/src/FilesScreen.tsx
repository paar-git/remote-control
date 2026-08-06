/**
 * The Files screen: this machine on the left, the server on the right.
 *
 * # Every name here is untrusted
 *
 * File names come from a filesystem anyone may have written to. They are rendered as
 * inert text — never as HTML, never as a link target — and the schema has already
 * stripped control characters and bidirectional overrides, without which a file called
 * `co<U+202E>gnp.exe` would display as `codexe.png`.
 *
 * Symlinks are shown *as* symlinks, with the target they record. The server does not
 * follow one that leaves its permitted roots, and this screen does not pretend a link
 * is the thing it points at.
 *
 * # Destructive actions state the full path
 *
 * There is no recycle bin behind this, so a delete is permanent. The confirmation shows
 * the resolved path and says so, because the difference between the right path and one
 * character off is the difference between a tidy-up and an outage.
 */

import { useCallback, useEffect, useState } from 'react';

import {
  type ConflictChoice,
  type FileEntry,
  type Listing,
  createRemoteDirectory,
  deleteRemotePath,
  downloadFile,
  getDefaultLocalDirectory,
  joinPath,
  listLocalDirectory,
  listRemoteDirectory,
  parentPath,
  uploadFile,
} from './api.js';
import { Badge, Button, ConfirmDialog, EmptyState, type Toast } from './components';
import { formatBytes, formatTimestamp } from './format.js';

/** Which side of the screen a pane is. */
type Side = 'local' | 'remote';

/** What a pane is currently showing. */
type PaneState =
  | { readonly status: 'loading' }
  | { readonly status: 'ready'; readonly listing: Listing }
  | { readonly status: 'error'; readonly message: string };

/** A transfer the operator started. */
interface Progress {
  readonly direction: 'upload' | 'download';
  readonly name: string;
}

export default function FilesScreen({
  onToast,
}: {
  readonly onToast: (toast: Toast) => void;
}): React.JSX.Element {
  const [localPath, setLocalPath] = useState<string | null>(null);
  const [remotePath, setRemotePath] = useState<string | null>(null);
  const [showHidden, setShowHidden] = useState(false);

  const [local, setLocal] = useState<PaneState>({ status: 'loading' });
  const [remote, setRemote] = useState<PaneState>({ status: 'loading' });

  const [selected, setSelected] = useState<{ side: Side; entry: FileEntry } | null>(null);
  const [busy, setBusy] = useState<Progress | null>(null);
  const [pendingDelete, setPendingDelete] = useState<FileEntry | null>(null);
  const [conflict, setConflict] = useState<ConflictChoice>('fail');

  // The local pane opens on the home directory. The remote pane has no equivalent until
  // the server tells us where it is, so it starts at the filesystem root and the
  // operator navigates.
  useEffect(() => {
    getDefaultLocalDirectory()
      .then(setLocalPath)
      .catch(() => {
        setLocal({
          status: 'error',
          message: 'Could not work out where to start browsing on this machine.',
        });
      });
  }, []);

  const loadLocal = useCallback(() => {
    if (localPath === null) return;
    setLocal({ status: 'loading' });

    listLocalDirectory(localPath, showHidden)
      .then((listing) => {
        setLocal({ status: 'ready', listing });
      })
      .catch((error: unknown) => {
        setLocal({
          status: 'error',
          message: error instanceof Error ? error.message : 'Could not read that folder.',
        });
      });
  }, [localPath, showHidden]);

  const loadRemote = useCallback(() => {
    if (remotePath === null) return;
    setRemote({ status: 'loading' });

    listRemoteDirectory(remotePath, showHidden)
      .then((listing) => {
        setRemote({ status: 'ready', listing });
      })
      .catch((error: unknown) => {
        setRemote({
          status: 'error',
          message:
            error instanceof Error ? error.message : 'Could not read that folder on the server.',
        });
      });
  }, [remotePath, showHidden]);

  useEffect(loadLocal, [loadLocal]);
  useEffect(loadRemote, [loadRemote]);

  /** Open a directory, or select a file. */
  const activate = useCallback((side: Side, entry: FileEntry, currentPath: string) => {
    if (entry.kind === 'directory') {
      const next = joinPath(currentPath, entry.name);
      if (side === 'local') setLocalPath(next);
      else setRemotePath(next);
      setSelected(null);
      return;
    }
    // A symlink is not followed by a click. Where it points is the server's decision,
    // and it may point outside what this session is allowed to reach.
    setSelected({ side, entry });
  }, []);

  const doUpload = useCallback(() => {
    if (selected?.side !== 'local') return;
    if (localPath === null || remotePath === null) return;

    const { entry } = selected;
    setBusy({ direction: 'upload', name: entry.name });

    uploadFile(joinPath(localPath, entry.name), joinPath(remotePath, entry.name), conflict)
      .then((result) => {
        onToast({
          kind: 'success',
          message: `Uploaded ${entry.name} — ${formatBytes(result.bytesTransferred)} verified.`,
        });
        loadRemote();
      })
      .catch((error: unknown) => {
        onToast({
          kind: 'error',
          message: error instanceof Error ? error.message : 'The upload failed.',
        });
      })
      .finally(() => {
        setBusy(null);
      });
  }, [conflict, loadRemote, localPath, onToast, remotePath, selected]);

  const doDownload = useCallback(() => {
    if (selected?.side !== 'remote') return;
    if (localPath === null || remotePath === null) return;

    const { entry } = selected;
    setBusy({ direction: 'download', name: entry.name });

    downloadFile(joinPath(localPath, entry.name), joinPath(remotePath, entry.name), conflict)
      .then((result) => {
        onToast({
          kind: 'success',
          message: `Downloaded ${entry.name} — ${formatBytes(result.bytesTransferred)} verified.`,
        });
        loadLocal();
      })
      .catch((error: unknown) => {
        onToast({
          kind: 'error',
          message: error instanceof Error ? error.message : 'The download failed.',
        });
      })
      .finally(() => {
        setBusy(null);
      });
  }, [conflict, loadLocal, localPath, onToast, remotePath, selected]);

  const doDelete = useCallback(
    (entry: FileEntry) => {
      if (remotePath === null) return;
      setPendingDelete(null);

      deleteRemotePath(joinPath(remotePath, entry.name), entry.kind === 'directory')
        .then(() => {
          onToast({ kind: 'success', message: `Deleted ${entry.name}.` });
          setSelected(null);
          loadRemote();
        })
        .catch((error: unknown) => {
          onToast({
            kind: 'error',
            message: error instanceof Error ? error.message : 'Could not delete it.',
          });
        });
    },
    [loadRemote, onToast, remotePath],
  );

  const doCreateFolder = useCallback(() => {
    if (remotePath === null) return;

    const name = window.prompt('Name for the new folder on the server');
    if (name === null || name.trim() === '') return;

    createRemoteDirectory(joinPath(remotePath, name.trim()))
      .then(() => {
        onToast({ kind: 'success', message: `Created ${name.trim()}.` });
        loadRemote();
      })
      .catch((error: unknown) => {
        onToast({
          kind: 'error',
          message: error instanceof Error ? error.message : 'Could not create the folder.',
        });
      });
  }, [loadRemote, onToast, remotePath]);

  const canUpload = selected?.side === 'local' && selected.entry.kind === 'file';
  const canDownload = selected?.side === 'remote' && selected.entry.kind === 'file';

  return (
    <section className="flex h-full flex-col">
      <header className="mb-4">
        <h2 className="text-base font-semibold">Files</h2>
        <p className="max-w-prose text-sm text-(--color-text-secondary)">
          This computer on the left, the server on the right. Every transfer is checked against a
          BLAKE3 checksum, and a file that does not match is discarded rather than saved.
        </p>
      </header>

      <div className="mb-3 flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-1.5 text-xs">
          <input
            type="checkbox"
            checked={showHidden}
            onChange={(event) => {
              setShowHidden(event.target.checked);
            }}
          />
          Show hidden files
        </label>

        <label className="flex items-center gap-1.5 text-xs">
          If it already exists
          <select
            value={conflict}
            onChange={(event) => {
              setConflict(event.target.value as ConflictChoice);
            }}
            className="rounded border border-(--color-border-subtle) bg-(--color-surface) px-2 py-1 text-xs"
          >
            <option value="fail">Stop and ask</option>
            <option value="overwrite">Replace it</option>
            <option value="rename">Keep both</option>
            <option value="resume">Resume it</option>
          </select>
        </label>

        <div className="ml-auto flex gap-1.5">
          <Button onClick={doUpload} disabled={!canUpload || busy !== null}>
            {busy?.direction === 'upload' ? 'Uploading…' : 'Upload →'}
          </Button>
          <Button onClick={doDownload} disabled={!canDownload || busy !== null}>
            {busy?.direction === 'download' ? 'Downloading…' : '← Download'}
          </Button>
        </div>
      </div>

      {busy !== null && (
        <p role="status" className="mb-2 text-xs text-(--color-text-secondary)">
          {busy.direction === 'upload' ? 'Uploading' : 'Downloading'} {busy.name}. Large files take
          a while — the checksum is verified before it is saved.
        </p>
      )}

      <div className="grid flex-1 gap-4 lg:grid-cols-2">
        <Pane
          title="This computer"
          path={localPath}
          state={local}
          selectedName={selected?.side === 'local' ? selected.entry.name : null}
          onNavigate={setLocalPath}
          onActivate={(entry) => {
            if (localPath !== null) activate('local', entry, localPath);
          }}
          onRefresh={loadLocal}
          actions={null}
        />

        <Pane
          title="Server"
          path={remotePath}
          state={remote}
          selectedName={selected?.side === 'remote' ? selected.entry.name : null}
          onNavigate={setRemotePath}
          onActivate={(entry) => {
            if (remotePath !== null) activate('remote', entry, remotePath);
          }}
          onRefresh={loadRemote}
          actions={
            <>
              <Button onClick={doCreateFolder} disabled={remotePath === null}>
                New folder
              </Button>
              <Button
                variant="danger"
                disabled={selected?.side !== 'remote'}
                onClick={() => {
                  if (selected?.side === 'remote') setPendingDelete(selected.entry);
                }}
              >
                Delete
              </Button>
            </>
          }
        />
      </div>

      <ConfirmDialog
        open={pendingDelete !== null}
        title="Delete this permanently?"
        destructive
        confirmLabel="Delete permanently"
        body={
          pendingDelete === null || remotePath === null ? null : (
            <>
              <p className="mb-2">
                This deletes it on the server immediately. There is no recycle bin behind this, so
                it cannot be undone.
              </p>
              <p className="mb-2 font-mono text-xs break-all">
                {joinPath(remotePath, pendingDelete.name)}
              </p>
              {pendingDelete.kind === 'directory' && (
                <p className="text-(--color-danger)">
                  This is a folder. Everything inside it will be deleted too.
                </p>
              )}
            </>
          )
        }
        onConfirm={() => {
          if (pendingDelete !== null) doDelete(pendingDelete);
        }}
        onCancel={() => {
          setPendingDelete(null);
        }}
      />
    </section>
  );
}

/** One side of the screen. */
function Pane({
  title,
  path,
  state,
  selectedName,
  onNavigate,
  onActivate,
  onRefresh,
  actions,
}: {
  readonly title: string;
  readonly path: string | null;
  readonly state: PaneState;
  readonly selectedName: string | null;
  readonly onNavigate: (path: string) => void;
  readonly onActivate: (entry: FileEntry) => void;
  readonly onRefresh: () => void;
  readonly actions: React.ReactNode;
}): React.JSX.Element {
  const [draft, setDraft] = useState(path ?? '');

  useEffect(() => {
    setDraft(path ?? '');
  }, [path]);

  const parent = path === null ? null : parentPath(path);

  return (
    <div className="flex min-h-0 flex-col rounded border border-(--color-border-subtle)">
      <div className="flex flex-wrap items-center gap-2 border-b border-(--color-border-subtle) p-2">
        <span className="text-sm font-semibold">{title}</span>
        <div className="ml-auto flex gap-1.5">{actions}</div>
      </div>

      <form
        className="flex gap-1.5 border-b border-(--color-border-subtle) p-2"
        onSubmit={(event) => {
          event.preventDefault();
          if (draft.trim() !== '') onNavigate(draft.trim());
        }}
      >
        <Button
          type="button"
          onClick={() => {
            if (parent !== null) onNavigate(parent);
          }}
          disabled={parent === null}
          title={parent === null ? 'Already at the top' : 'Go up one folder'}
        >
          ↑
        </Button>
        <label htmlFor={`path-${title}`} className="sr-only">
          {title} path
        </label>
        <input
          id={`path-${title}`}
          value={draft}
          onChange={(event) => {
            setDraft(event.target.value);
          }}
          spellCheck={false}
          className="min-w-0 flex-1 rounded border border-(--color-border-subtle) bg-(--color-surface) px-2 py-1 font-mono text-xs"
        />
        <Button type="submit">Go</Button>
        <Button type="button" onClick={onRefresh}>
          ⟳
        </Button>
      </form>

      <div className="min-h-64 flex-1 overflow-auto">
        {state.status === 'loading' && (
          <p role="status" className="p-3 text-sm text-(--color-text-secondary)">
            Loading…
          </p>
        )}

        {state.status === 'error' && (
          <div role="alert" className="p-3 text-sm">
            <p className="mb-2 text-(--color-danger)">{state.message}</p>
            <Button onClick={onRefresh}>Try again</Button>
          </div>
        )}

        {state.status === 'ready' && state.listing.entries.length === 0 && (
          <div className="p-3">
            <EmptyState title="This folder is empty" body="Nothing here to show." />
          </div>
        )}

        {state.status === 'ready' && state.listing.entries.length > 0 && (
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 bg-(--color-surface) text-(--color-text-secondary)">
              <tr>
                <th scope="col" className="p-1.5 font-medium">
                  Name
                </th>
                <th scope="col" className="p-1.5 text-right font-medium">
                  Size
                </th>
                <th scope="col" className="p-1.5 font-medium">
                  Modified
                </th>
              </tr>
            </thead>
            <tbody>
              {state.listing.entries.map((entry) => (
                <tr
                  key={entry.name}
                  className={entry.name === selectedName ? 'bg-(--color-border-subtle)' : undefined}
                >
                  <td className="p-1.5">
                    <button
                      type="button"
                      onClick={() => {
                        onActivate(entry);
                      }}
                      className="flex items-center gap-1.5 text-left"
                    >
                      <span aria-hidden="true">{icon(entry.kind)}</span>
                      {/* Rendered as text. The schema has already stripped control
                          characters and bidirectional overrides. */}
                      <span className={entry.hidden ? 'opacity-60' : undefined}>{entry.name}</span>
                      {entry.kind === 'symlink' && (
                        <Badge tone="warning">link → {entry.symlinkTarget ?? 'unknown'}</Badge>
                      )}
                      {!entry.readable && entry.kind !== 'symlink' && <Badge>no access</Badge>}
                    </button>
                  </td>
                  <td className="p-1.5 text-right tabular-nums whitespace-nowrap">
                    {entry.kind === 'directory' ? '—' : formatBytes(entry.sizeBytes)}
                  </td>
                  <td className="p-1.5 whitespace-nowrap text-(--color-text-secondary)">
                    {formatTimestamp(entry.modifiedMs)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {state.status === 'ready' && state.listing.truncated && (
        <p className="border-t border-(--color-border-subtle) p-2 text-xs text-(--color-text-secondary)">
          This folder has more entries than can be shown at once. Narrow it down by opening a
          subfolder.
        </p>
      )}
    </div>
  );
}

/** A glyph for an entry kind. Decorative; the kind is also conveyed in text. */
function icon(kind: FileEntry['kind']): string {
  switch (kind) {
    case 'directory':
      return '📁';
    case 'symlink':
      return '🔗';
    case 'file':
      return '📄';
    case 'other':
      return '⚙';
  }
}
