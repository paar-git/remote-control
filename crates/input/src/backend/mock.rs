//! An [`InputSink`](crate::InputSink) that records instead of injecting.
//!
//! Every test in this crate and in the agent asserts against the exact sequence of OS
//! calls a real backend would have made. That is what lets the pipeline be verified on
//! a machine with no desktop, no display server and no accessibility permission —
//! including CI containers on all three platforms.

use rc_protocol::{Intent, InputCapability, InputFailure, KeyState, MouseButton, PhysicalKey};

use crate::{HostOs, InputSink, Result, intent};

/// One call a backend received.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum Call {
    /// Pointer moved to a normalised position on a display.
    PointerMove {
        /// Horizontal, 0.0–1.0.
        x: f32,
        /// Vertical, 0.0–1.0.
        y: f32,
        /// Which display.
        display: u8,
    },
    /// A mouse button transition.
    Button {
        /// Which button.
        button: MouseButton,
        /// Down or up.
        state: KeyState,
    },
    /// A scroll.
    Scroll {
        /// Horizontal delta.
        dx: f32,
        /// Vertical delta.
        dy: f32,
    },
    /// A key transition.
    Key {
        /// Which key.
        key: PhysicalKey,
        /// Down or up.
        state: KeyState,
    },
}

/// Records calls; optionally fails them all.
#[derive(Debug, Default)]
pub struct MockSink {
    calls: Vec<Call>,
    capability: Option<InputCapability>,
    fail_with: Option<InputFailure>,
}

impl MockSink {
    /// A sink that accepts everything.
    #[must_use]
    pub fn new() -> Self {
        Self {
            calls: Vec::new(),
            capability: None,
            fail_with: None,
        }
    }

    /// A sink that refuses everything with `reason`, for testing failure reporting.
    #[must_use]
    pub fn failing(reason: InputFailure) -> Self {
        Self {
            calls: Vec::new(),
            capability: Some(InputCapability::Unavailable { reason }),
            fail_with: Some(reason),
        }
    }

    /// Everything received so far, in order.
    #[must_use]
    pub fn calls(&self) -> &[Call] {
        &self.calls
    }

    /// Only the key transitions, which is what chord assertions care about.
    #[must_use]
    pub fn key_calls(&self) -> Vec<(PhysicalKey, KeyState)> {
        self.calls
            .iter()
            .filter_map(|call| match *call {
                Call::Key { key, state } => Some((key, state)),
                _ => None,
            })
            .collect()
    }

    /// Forget everything recorded.
    pub fn clear(&mut self) {
        self.calls.clear();
    }

    fn record(&mut self, call: Call) -> Result<()> {
        if let Some(reason) = self.fail_with {
            return Err(crate::InputError::Refused(reason));
        }
        self.calls.push(call);
        Ok(())
    }
}

impl InputSink for MockSink {
    fn pointer_move(&mut self, x: f32, y: f32, display: u8) -> Result<()> {
        self.record(Call::PointerMove { x, y, display })
    }

    fn button(&mut self, button: MouseButton, state: KeyState) -> Result<()> {
        self.record(Call::Button { button, state })
    }

    fn scroll(&mut self, dx: f32, dy: f32) -> Result<()> {
        self.record(Call::Scroll { dx, dy })
    }

    fn key(&mut self, key: PhysicalKey, state: KeyState) -> Result<()> {
        self.record(Call::Key { key, state })
    }

    fn capability(&self) -> InputCapability {
        self.capability.unwrap_or(InputCapability::Full)
    }

    fn host_os(&self) -> Option<HostOs> {
        // Tests set the OS explicitly through `IntentRenderer`; a bare mock reports
        // whatever this build runs on.
        HostOs::current()
    }

    fn supported_intents(&self) -> Vec<Intent> {
        self.host_os().map(intent::supported).unwrap_or_default()
    }
}
