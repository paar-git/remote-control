//! A capture source with no operating system behind it.

use rc_protocol::desktop::DisplayInfo;

use super::{CaptureSource, CapturedFrame};
use crate::{Result, VideoError};

/// A scripted capture source for tests.
#[derive(Debug)]
pub struct MockSource {
    width: u32,
    height: u32,
    solid: [u8; 4],
    queued: Vec<CapturedFrame>,
    fail_next: Option<VideoError>,
}

impl MockSource {
    /// A source presenting one display of `width` by `height`, initially black.
    #[must_use]
    pub const fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            solid: [0, 0, 0, 255],
            queued: Vec::new(),
            fail_next: None,
        }
    }

    /// Make every subsequent generated frame this colour.
    pub const fn set_solid(&mut self, rgba: [u8; 4]) {
        self.solid = rgba;
    }

    /// Hand back `frame` before any generated one.
    pub fn push(&mut self, frame: CapturedFrame) {
        self.queued.push(frame);
    }

    /// Fail the next `grab` with `err`, once.
    pub fn fail_next(&mut self, err: VideoError) {
        self.fail_next = Some(err);
    }
}

impl CaptureSource for MockSource {
    fn displays(&self) -> Result<Vec<DisplayInfo>> {
        Ok(vec![DisplayInfo {
            index: 0,
            name: "mock".to_owned(),
            width: self.width,
            height: self.height,
            scale_factor: 1.0,
            origin_x: 0,
            origin_y: 0,
            primary: true,
            refresh_hz: Some(60),
        }])
    }

    fn grab(&mut self, index: u8) -> Result<CapturedFrame> {
        if index != 0 {
            return Err(VideoError::NoSuchDisplay(index));
        }
        if let Some(err) = self.fail_next.take() {
            return Err(err);
        }
        if !self.queued.is_empty() {
            return Ok(self.queued.remove(0));
        }
        let pixels = (self.width as usize) * (self.height as usize);
        let mut rgba = Vec::with_capacity(pixels * 4);
        for _ in 0..pixels {
            rgba.extend_from_slice(&self.solid);
        }
        Ok(CapturedFrame {
            width: self.width,
            height: self.height,
            rgba,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mock_hands_back_the_frames_it_was_given() {
        let mut source = MockSource::new(4, 2);
        source.set_solid([10, 20, 30, 255]);

        let frame = source.grab(0).expect("the mock always has display 0");

        assert_eq!(frame.width, 4);
        assert_eq!(frame.height, 2);
        assert_eq!(frame.rgba.len(), 4 * 2 * 4, "four bytes per pixel");
        assert_eq!(&frame.rgba[0..4], &[10, 20, 30, 255]);
    }

    #[test]
    fn asking_for_a_display_that_is_not_there_names_the_index() {
        // An operator whose second monitor was unplugged mid-session needs the error
        // to say which display vanished, not just that something failed.
        let mut source = MockSource::new(4, 2);
        let err = source.grab(7).expect_err("display 7 does not exist");
        assert!(matches!(err, VideoError::NoSuchDisplay(7)));
    }

    #[test]
    fn a_capture_failure_is_reported_rather_than_papered_over() {
        let mut source = MockSource::new(4, 2);
        source.fail_next(VideoError::Unsupported("wayland has no capture path"));
        let err = source
            .grab(0)
            .expect_err("the injected failure must surface");
        assert!(matches!(err, VideoError::Unsupported(_)));
        // The failure is consumed, not sticky.
        assert!(source.grab(0).is_ok());
    }
}
