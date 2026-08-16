/**
 * Keeping this machine's clipboard and the remote one in step, without an echo.
 *
 * # The loop is the whole problem
 *
 * Both ends watch their own clipboard and publish what they see, so the naive
 * arrangement never settles: this end publishes, the host writes it, the host's watcher
 * notices and publishes it back, this end writes it, and round it goes. `rc_clipboard`
 * holds the same state on the Rust side for the same reason — see
 * `crates/clipboard/src/sync.rs`. Both ends need it: either one alone still lets the
 * other bounce a value back.
 *
 * # Why the text is held here and not in Rust
 *
 * The Rust side deliberately keeps only a digest, because it is a relay that has no
 * other reason to hold clipboard text. This module is not a relay: it is the thing that
 * actually reads and writes the operator's clipboard, so the text is already in this
 * page's memory either way. It is dropped on {@link ClipboardSync.reset}, which the
 * surface calls when a session stops sharing.
 */

/** Mirrors `MAX_CLIPBOARD_BYTES` in `crates/clipboard/src/sync.rs`. */
export const MAX_CLIPBOARD_BYTES = 1024 * 1024;

/** What this end last saw, so an echo can be recognised. */
export class ClipboardSync {
  #seen: string | null = null;

  /**
   * Whether locally-observed text should be published to the host.
   *
   * `false` for text that came *from* the host, which is what breaks the loop, and for
   * empty or oversized text.
   */
  shouldPublish(text: string): boolean {
    return this.#record(text);
  }

  /** Whether text the host published should be written to this clipboard. */
  shouldApply(text: string): boolean {
    return this.#record(text);
  }

  /** Forget what was seen. A new session is a new peer, sent nothing so far. */
  reset(): void {
    this.#seen = null;
  }

  /** Note text as seen, reporting whether it is news. */
  #record(text: string): boolean {
    // `length` is UTF-16 units, which undercounts against the Rust byte limit for
    // non-ASCII. The exact boundary is checked in Rust, where the bytes actually are;
    // this only avoids sending something obviously enormous across the IPC boundary.
    if (text === '' || text.length > MAX_CLIPBOARD_BYTES) return false;
    if (this.#seen === text) return false;
    this.#seen = text;
    return true;
  }
}
