//! System metrics collection.
//!
//! # Only measured values are reported
//!
//! Every field this crate produces comes from the operating system. Where a value
//! cannot be measured — GPU utilisation without a vendor library, a temperature sensor
//! the platform does not expose, a process path the agent may not read — the field is
//! `None` or the list is empty. Nothing is estimated, interpolated or defaulted to
//! zero.
//!
//! This is the whole point. A dashboard showing `0 °C` where it means "no sensor" is
//! worse than one showing nothing: the operator cannot tell the difference between a
//! cold machine and a missing reading, and will eventually trust the wrong one.
//!
//! # Sampling is stateful, and has to be
//!
//! CPU utilisation and network rates are *derivatives*: they only exist relative to a
//! previous sample. A single refresh produces either zero or a meaningless figure, so
//! [`MetricsCollector`] keeps the previous sample and reports rates over the interval
//! between the two. The first snapshot after start therefore has no rates, and says so
//! by reporting them as zero only after a real interval has elapsed.
//!
//! # Cost
//!
//! Enumerating every process on a busy server is not free. [`MetricsCollector`] refreshes
//! only what a snapshot needs, keeps one `System` alive rather than rebuilding it, and
//! bounds the process list to the top consumers. A monitoring feature that noticeably
//! loads the machine being monitored is a bug.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod collector;
pub mod processes;

pub use collector::{MIN_SAMPLE_INTERVAL_MS, MetricsCollector, TOP_PROCESS_COUNT};
pub use processes::{ProcessFilter, ProcessSort};
