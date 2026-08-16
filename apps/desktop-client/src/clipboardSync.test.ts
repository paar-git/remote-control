import { describe, expect, it } from 'vitest';

import { ClipboardSync, MAX_CLIPBOARD_BYTES } from './clipboardSync.js';

describe('ClipboardSync', () => {
  it('does not publish back what the host just sent', () => {
    // The echo this exists to stop. Both ends need this state: either one alone still
    // lets the other bounce the value back forever.
    const sync = new ClipboardSync();
    expect(sync.shouldApply('hunter2')).toBe(true);
    expect(sync.shouldPublish('hunter2')).toBe(false);
  });

  it('does not reapply text the host echoes back unchanged', () => {
    const sync = new ClipboardSync();
    expect(sync.shouldPublish('hunter2')).toBe(true);
    expect(sync.shouldApply('hunter2')).toBe(false);
  });

  it('publishes something genuinely newly copied', () => {
    const sync = new ClipboardSync();
    expect(sync.shouldPublish('first')).toBe(true);
    expect(sync.shouldPublish('second')).toBe(true);
  });

  it('publishes the same text once, however often it is observed', () => {
    // A focus-driven read sees the same clipboard every time the window is entered;
    // only a change is news.
    const sync = new ClipboardSync();
    expect(sync.shouldPublish('same')).toBe(true);
    expect(sync.shouldPublish('same')).toBe(false);
  });

  it('publishes earlier text again when the operator copies it back', () => {
    // Only the most recent observation is remembered; keeping every value ever seen
    // would be a growing store of other people's passwords.
    const sync = new ClipboardSync();
    expect(sync.shouldPublish('alpha')).toBe(true);
    expect(sync.shouldPublish('beta')).toBe(true);
    expect(sync.shouldPublish('alpha')).toBe(true);
  });

  it('ignores an empty clipboard', () => {
    const sync = new ClipboardSync();
    expect(sync.shouldPublish('')).toBe(false);
    expect(sync.shouldApply('')).toBe(false);
  });

  it('drops oversized text rather than truncating it', () => {
    // Half a document pasted on the far end reads as corruption.
    const sync = new ClipboardSync();
    expect(sync.shouldPublish('x'.repeat(MAX_CLIPBOARD_BYTES + 1))).toBe(false);
  });

  it('keeps what it already knew when it refuses oversized text', () => {
    // Otherwise the text before it would be republished on the next observation.
    const sync = new ClipboardSync();
    expect(sync.shouldPublish('kept')).toBe(true);
    expect(sync.shouldPublish('x'.repeat(MAX_CLIPBOARD_BYTES + 1))).toBe(false);
    expect(sync.shouldPublish('kept')).toBe(false);
  });

  it('starts fresh after a reset', () => {
    const sync = new ClipboardSync();
    expect(sync.shouldPublish('carried')).toBe(true);
    sync.reset();
    expect(sync.shouldPublish('carried')).toBe(true);
  });
});
