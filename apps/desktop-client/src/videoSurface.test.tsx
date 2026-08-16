import { render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import * as videoApi from './videoApi.js';
import { VideoSurface } from './VideoSurface';

vi.mock('./videoApi.js', async (importOriginal) => {
  const actual: typeof videoApi = await importOriginal();
  return {
    ...actual,
    startStream: vi.fn(),
    stopStream: vi.fn(() => Promise.resolve(null)),
    requestKeyframe: vi.fn(() => Promise.resolve(null)),
    listenStreamEnded: vi.fn(() => Promise.resolve(() => undefined)),
  };
});

const STARTED: videoApi.StreamStarted = {
  displayIndex: 0,
  codec: 'raw_rgba',
  width: 1920,
  height: 1080,
  hardwareAccelerated: false,
};

describe('VideoSurface', () => {
  beforeEach(() => {
    vi.mocked(videoApi.startStream).mockImplementation((displayIndex) => {
      // Display 9 stands in for "the agent refused" — every other index starts fine.
      if (displayIndex === 9) {
        return Promise.reject(new Error('Could not start capturing that display.'));
      }
      return Promise.resolve(STARTED);
    });
  });

  it('sizes the canvas to the stream the agent actually started', async () => {
    // A canvas left at its default size silently scales every frame, which reads as
    // a blurry remote rather than as a bug in this component.
    render(<VideoSurface displayIndex={0} fitted />);

    const canvas = await screen.findByTestId<HTMLCanvasElement>('video-surface');
    await waitFor(() => {
      expect(canvas.width).toBe(1920);
      expect(canvas.height).toBe(1080);
    });
  });

  it('says the stream failed rather than showing an empty black rectangle', async () => {
    // Indistinguishable states are the failure this project keeps guarding against:
    // a black canvas could be a locked remote screen or a dead stream.
    render(<VideoSurface displayIndex={9} fitted />);
    expect(await screen.findByRole('alert')).toHaveTextContent(/could not start/i);
  });

  it('says the stream failed when it dies mid-session, not just at start', async () => {
    // Otherwise a stream that dies after starting looks identical to a screen where
    // nothing is happening.
    let endStream: ((ended: videoApi.StreamEnded) => void) | undefined;
    vi.mocked(videoApi.listenStreamEnded).mockImplementation((handler) => {
      endStream = handler;
      return Promise.resolve(() => undefined);
    });

    render(<VideoSurface displayIndex={0} fitted />);
    await screen.findByTestId('video-surface');

    await waitFor(() => {
      expect(endStream).toBeDefined();
    });
    endStream?.({
      code: 'channel_closed',
      message: 'The connection to the other device was lost.',
    });

    expect(await screen.findByRole('alert')).toHaveTextContent(/connection.*lost/i);
  });
});
