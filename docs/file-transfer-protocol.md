# File transfer

How files move between the client and the server, and what stops a path from reaching
somewhere it should not.

## Path safety

Every path in a file message is chosen by the peer. Three attack classes follow, and all
three are closed before any filesystem call happens.

| Attack | Example | Closed by |
|---|---|---|
| Traversal | `roots/../../etc/shadow` | Lexical normalisation before any I/O |
| Symlink escape | `roots/link` → `/etc` | Canonicalising and re-checking after resolution |
| Reserved names | `roots/CON`, `roots/x.` | An explicit refusal list |

### Why the check runs twice

A path is normalised **lexically** first: `..` components are resolved without touching
the filesystem, and the result is checked against the configured roots. Then, if the
path exists, it is **canonicalised** by the operating system — which follows symlinks —
and checked again.

Neither pass alone is sufficient:

- The lexical pass misses a symlink pointing out of a root, because it never asks the
  filesystem where anything actually is.
- The canonical pass cannot run on a path that does not exist yet, which is *every*
  upload destination and every new directory.

For a path that does not exist, its **parent** is canonicalised and checked instead.
Without that, a peer could plant a file through a symlinked parent directory.

### Refusals do not describe the filesystem

Traversal and symlink escape report the **same** error. Distinguishing them would tell a
peer whether a path exists and whether it is a link — a map of a filesystem it was just
refused access to.

Error messages never echo the path they were given, either. A message that repeats
attacker-supplied text carries it into a log, a toast and a bug report.

### Reserved names

`CON`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9` and their kin are device names on Windows,
with any extension. `CON.txt` does not create a file — it opens the console. A transfer
to one would appear to succeed and write nowhere, which is worse than failing.

Names ending in a space or a dot are refused for the same reason: Windows silently
strips both, so `secret.txt.` opens `secret.txt`. A name that does not mean what it says
is a name to refuse.

## Confinement

`features.file_transfer_roots` in the agent's configuration confines access. An empty
list means the whole filesystem — the right default for a server the operator
administers, since confining them to one directory on their own machine would be
theatre. It is a deliberate choice, stated in the configuration and in the code, not an
accident.

If roots are configured but cannot be applied, the agent fails closed to **no** file
access rather than to unconfined access.

## Listings

Symlinks are reported *as* symlinks, with the target they record on disk. They are never
followed for metadata: a link to a 40 GB file elsewhere would otherwise be listed as a
40 GB file sitting in that directory, which is not what is there, and is exactly the
confusion a symlink escape relies on.

An entry the agent cannot stat is still listed, marked unreadable. An operator needs to
see that something is there even when the agent cannot look at it — not least in order
to delete it.

Listings are bounded at 10,000 entries and say when they were truncated, so a client
shows "the first 10,000 of many" rather than waiting for a frame that would exceed the
channel ceiling.

## Transfers

### Verified, not assumed

Every transfer agrees a whole-file BLAKE3 digest **before the first byte moves**. On
completion the received file is hashed and compared.

A mismatch **discards** the file. It is not kept with a warning, on either side.

A file that is silently wrong is worse than a transfer that failed: the failure is
discovered now, by the person who can retry it; the corruption is discovered later, by
whoever depended on it.

### Written aside, renamed in

An upload is written to `destination.rc-partial` and renamed into place only after its
checksum verifies.

So an interrupted transfer leaves a partial file with an obviously incomplete name,
never a truncated file under the real one — which is what would happen if a
half-finished upload overwrote a good file in place. A failed transfer leaves the
original file exactly as it was.

The same applies in the download direction, on the client.

### Chunks are ordered and bounded

Chunks must arrive at exactly the offset the transfer expects. An arbitrary offset would
let a peer write anywhere in the file, including past the size it agreed, and would
leave holes that no checksum could explain.

A chunk that would take the file past its agreed total size is refused.

Chunks draw no per-chunk reply. A round trip per chunk would halve throughput for no
added safety, since the checksum already covers the result.

### Resuming verifies the prefix

Continuing an interrupted upload hashes the bytes already on disk over the claimed range
and compares them against the client's digest for that range.

A resume that trusted the offset alone would splice two different files together and
produce something that passed no check until the final digest — by which point the whole
transfer has been spent.

A cancelled transfer **keeps** its partial file. A cancelled transfer is usually one the
operator means to resume, and deleting the work would make Cancel and Restart the same
button.

## Authorization

Reading needs `FileRead`; anything that changes the filesystem needs `FileWrite`. Both
are checked **per message** against the live session, not once when the channel opens,
so a device revoked mid-connection stops being served immediately.

The split is what makes a View Only device useful: it can browse and download without
being able to alter anything.

Which capability a message needs is decided by an explicit list of read-only operations.
A message added later falls through to the write half — a new operation needlessly gated
behind write access is a nuisance; a new operation that changes the filesystem treated as
a read is a hole.

## Deletion

There is no recycle bin in this build. Every delete is permanent, and the client says so
in the confirmation rather than implying a recoverable one.

Recursion is never inferred. Deleting a non-empty directory requires the client to have
asked for it explicitly, because the difference between the right path and one character
off is the difference between a tidy-up and an outage.

A symlink is removed as a link, never followed. Following it would delete the target,
which may be outside the permitted roots entirely.

## Limits

| Limit | Value | Why |
|---|---|---|
| Chunk size | 256 KiB | Not four thousand round trips for a gigabyte, still far inside the channel ceiling |
| Concurrent transfers per connection | 8 | Bounded agent state |
| Directory entries per listing | 10,000 | Bounded frame size |
| Maximum file size | `features.max_transfer_bytes` | Operator-configured, 64 GiB by default |

## Not implemented

- **Folder upload and download.** Only individual files. A recursive transfer needs a
  queue with progress and a cancel path, which is more than a single message can carry.
- **Copy of a directory.** Refused rather than silently copying one file.
- **A transfer queue**, pause and resume from the UI, and per-transfer progress. The
  library supports resuming; nothing yet drives it from the interface.
- **Recycle bin or trash**, archive creation and extraction, file previews, and
  drag-and-drop.
- **Disk-space validation** before a transfer starts. A full disk is reported when the
  write fails rather than predicted.
