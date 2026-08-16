/**
 * Tauri command wrappers for the video stream — Task 10's Rust surface, typed for the
 * frontend that consumes it.
 *
 * Kept out of `api.ts` rather than added to it: `api.ts` carries the repo owner's own
 * uncommitted, in-flight work, and this task was told not to touch it. `call()` itself
 * would happily accept a `Channel` argument alongside the rest — nothing about the
 * `Channel` demanded a separate file.
 */

import { Channel } from '@tauri-apps/api/core';
import { z } from 'zod';

import { call } from './ipc.js';

/** A capturable display, as reported by the connected agent. */
export const displayInfoSchema = z.object({
  index: z.number().int().nonnegative(),
  name: z.string(),
  width: z.number().int().positive(),
  height: z.number().int().positive(),
  scaleFactor: z.number().positive(),
  primary: z.boolean(),
});

export type DisplayInfo = z.infer<typeof displayInfoSchema>;

/** What the agent actually started, once negotiation is done. */
export const streamStartedSchema = z.object({
  displayIndex: z.number().int().nonnegative(),
  codec: z.string().min(1),
  width: z.number().int().positive(),
  height: z.number().int().positive(),
  hardwareAccelerated: z.boolean(),
});

export type StreamStarted = z.infer<typeof streamStartedSchema>;

/**
 * Why a stream ended, carried on `video://stream-ended`.
 *
 * Fires on every way a stream can stop — a mid-stream agent error, a clean stop, the
 * channel closing, a transport failure, a decode failure — so the surface showing the
 * stream can say why, rather than leaving a screen that simply stopped updating, which
 * is indistinguishable from a locked remote desktop.
 */
export const streamEndedSchema = z.object({
  code: z.string().min(1),
  message: z.string().min(1),
});

export type StreamEnded = z.infer<typeof streamEndedSchema>;

/** List the displays the connected agent can capture. */
export function listDisplays(): Promise<DisplayInfo[]> {
  return call('video_list_displays', z.array(displayInfoSchema));
}

/**
 * Start streaming a display.
 *
 * Frames arrive on `onFrame` as raw `ArrayBuffer`s in the wire format `video.ts`
 * parses — one call per changed region, not per full frame, and never JSON.
 */
export function startStream(
  displayIndex: number,
  maxFps: number,
  onFrame: (buffer: ArrayBuffer) => void,
): Promise<StreamStarted> {
  const channel = new Channel<ArrayBuffer>();
  channel.onmessage = onFrame;
  return call('video_start_stream', streamStartedSchema, {
    displayIndex,
    maxFps,
    onFrame: channel,
  });
}

/** Stop the current stream. */
export function stopStream(): Promise<null> {
  return call('video_stop_stream', z.null());
}

/** Ask the agent for a fresh keyframe, e.g. after the operator notices tearing. */
export function requestKeyframe(): Promise<null> {
  return call('video_request_keyframe', z.null());
}

/**
 * Subscribe to the end of a video stream.
 *
 * Worth listening for rather than assuming silence means an idle screen: a stream that
 * died mid-session must say so, not leave its last frame on screen looking current.
 */
export async function listenStreamEnded(
  handler: (ended: StreamEnded) => void,
): Promise<() => void> {
  const { listen } = await import('@tauri-apps/api/event');

  return listen('video://stream-ended', (event) => {
    const parsed = streamEndedSchema.safeParse(event.payload);
    if (parsed.success) handler(parsed.data);
  });
}
