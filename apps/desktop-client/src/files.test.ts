/**
 * Tests for the path helpers the Files screen navigates with.
 *
 * These matter more than they look. The two panes can be on different platforms — a
 * Windows client browsing a Linux server is the ordinary case — so the separator has to
 * follow the *pane*, not the machine the code is running on. Getting that wrong builds
 * paths the far side cannot resolve, and the failure looks like a permissions problem
 * rather than a client bug.
 */

import { describe, expect, it } from 'vitest';

import { fileEntrySchema, joinPath, listingSchema, parentPath } from './api.js';

describe('joinPath', () => {
  it('uses the separator of the path it was given, not of this machine', () => {
    expect(joinPath('/home/koren', 'notes.txt')).toBe('/home/koren/notes.txt');
    expect(joinPath('C:\\Users\\koren', 'notes.txt')).toBe('C:\\Users\\koren\\notes.txt');
  });

  it('does not double a separator that is already there', () => {
    expect(joinPath('/home/koren/', 'notes.txt')).toBe('/home/koren/notes.txt');
    expect(joinPath('C:\\Users\\koren\\', 'notes.txt')).toBe('C:\\Users\\koren\\notes.txt');
  });

  it('joins onto a drive root', () => {
    expect(joinPath('C:', 'Windows')).toBe('C:\\Windows');
  });

  it('joins onto the filesystem root without producing a double slash', () => {
    expect(joinPath('/', 'etc')).toBe('/etc');
  });

  it('carries a hostile name through unchanged', () => {
    // Mangling it here would mean the path built could not act on the real file. The
    // schema strips what is dangerous to *render*; the path keeps what is on disk.
    const name = 'file with spaces and (brackets).txt';
    expect(joinPath('/tmp', name)).toBe(`/tmp/${name}`);
  });
});

describe('parentPath', () => {
  it('climbs one level', () => {
    expect(parentPath('/home/koren/docs')).toBe('/home/koren');
    expect(parentPath('C:\\Users\\koren\\docs')).toBe('C:\\Users\\koren');
  });

  it('ignores a trailing separator', () => {
    expect(parentPath('/home/koren/docs/')).toBe('/home/koren');
  });

  it('reports the POSIX root as the parent of a top-level directory', () => {
    expect(parentPath('/etc')).toBe('/');
  });

  it('returns null at a root, so the UI can disable the button', () => {
    // Offering an "up" button that does nothing is worse than not offering one.
    expect(parentPath('/')).toBeNull();
    expect(parentPath('C:\\')).toBeNull();
  });

  it('climbs to the drive root rather than to a bare drive letter', () => {
    // `C:` is not a directory — it means "the working directory on drive C", which is
    // not what an operator clicking "up" is asking for.
    expect(parentPath('C:\\Users')).toBe('C:\\');
  });
});

describe('file listing schema', () => {
  const entry = {
    name: 'notes.txt',
    kind: 'file',
    sizeBytes: 42,
    modifiedMs: 1_700_000_000_000,
    hidden: false,
    readable: true,
    writable: true,
    permissions: 'rw-r--r--',
    symlinkTarget: null,
  };

  it('accepts a well-formed entry', () => {
    expect(() => fileEntrySchema.parse(entry)).not.toThrow();
  });

  it('strips a bidirectional override from a file name', () => {
    // Without this, `co<U+202E>gnp.exe` displays as `codexe.png` — an executable
    // wearing an image's name.
    const parsed = fileEntrySchema.parse({ ...entry, name: 'co\u202egnp.exe' });

    expect(parsed.name).not.toContain('\u202e');
  });

  it('strips control characters from a file name', () => {
    const parsed = fileEntrySchema.parse({ ...entry, name: 'two\nlines.txt' });

    expect(parsed.name).not.toContain('\n');
  });

  it('rejects a kind the backend cannot produce', () => {
    expect(() => fileEntrySchema.parse({ ...entry, kind: 'executable' })).toThrow();
  });

  it('accepts a listing that reports itself truncated', () => {
    const listing = listingSchema.parse({
      path: '/var/log',
      entries: [entry],
      truncated: true,
    });

    expect(listing.truncated).toBe(true);
    expect(listing.entries).toHaveLength(1);
  });

  it('keeps a symlink target so the operator can see where it points', () => {
    const parsed = fileEntrySchema.parse({
      ...entry,
      kind: 'symlink',
      symlinkTarget: '../../etc',
    });

    expect(parsed.symlinkTarget).toBe('../../etc');
  });
});
