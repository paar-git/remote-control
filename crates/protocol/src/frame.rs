//! Length-prefixed framing.
//!
//! Wire layout of a single frame:
//!
//! ```text
//! ┌────────┬─────────┬──────────┬──────────────────┐
//! │ magic  │ channel │  length  │      body        │
//! │ 2 bytes│ 1 byte  │ 4 bytes  │  `length` bytes  │
//! │ 0x52 43│  u8     │ u32 BE   │  postcard blob   │
//! └────────┴─────────┴──────────┴──────────────────┘
//! ```
//!
//! The decoder validates `length` against the channel's limit **before** reserving any
//! memory, so a hostile peer cannot trigger a large allocation with a 7-byte header.

use bytes::{Buf, BufMut, BytesMut};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::{ProtocolError, Result};
use crate::limits;

/// Frame magic: ASCII `RC`.
pub const MAGIC: [u8; 2] = [0x52, 0x43];

/// Number of bytes preceding the body.
pub const HEADER_LEN: usize = 7;

/// Logical stream a frame belongs to.
///
/// Each channel is carried on its own QUIC stream, so a large file transfer cannot
/// head-of-line block latency-sensitive input events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum Channel {
    /// Handshake, authorization, session lifecycle, dashboards, power actions.
    Control = 1,
    /// Directory listings, transfer chunks and acknowledgements.
    FileTransfer = 3,
    /// Encoded video frames from host to client.
    Video = 4,
    /// Mouse and keyboard events from client to host.
    Input = 5,
    /// Periodic system metrics.
    Metrics = 6,
}

impl Channel {
    /// Maximum body size permitted on this channel.
    #[must_use]
    pub const fn max_frame_len(self) -> usize {
        match self {
            Self::Control | Self::Metrics => limits::MAX_CONTROL_FRAME,
            Self::FileTransfer => limits::MAX_FILE_FRAME,
            Self::Video => limits::MAX_VIDEO_FRAME,
            // Input events are tiny; keep the ceiling low to blunt flooding.
            Self::Input => 4 * 1024,
        }
    }

    /// Map a wire byte to a channel.
    ///
    /// # Errors
    /// Returns [`ProtocolError::UnknownChannel`] for unrecognised values.
    pub const fn from_wire(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Control),
            3 => Ok(Self::FileTransfer),
            4 => Ok(Self::Video),
            5 => Ok(Self::Input),
            6 => Ok(Self::Metrics),
            other => Err(ProtocolError::UnknownChannel(other)),
        }
    }

    /// The wire byte for this channel.
    #[must_use]
    pub const fn to_wire(self) -> u8 {
        self as u8
    }
}

/// Serialize `message` into a complete frame appended to `dst`.
///
/// # Errors
/// Fails if the message cannot be serialized, or if the encoded body would exceed the
/// channel's limit.
pub fn encode<T: Serialize>(channel: Channel, message: &T, dst: &mut BytesMut) -> Result<()> {
    let body = postcard::to_stdvec(message).map_err(|_| ProtocolError::Encode)?;

    if body.is_empty() {
        return Err(ProtocolError::EmptyFrame);
    }
    let limit = channel.max_frame_len();
    if body.len() > limit {
        return Err(ProtocolError::FrameTooLarge {
            actual: body.len(),
            limit,
        });
    }

    dst.reserve(HEADER_LEN + body.len());
    dst.put_slice(&MAGIC);
    dst.put_u8(channel.to_wire());
    // Checked directly above: body.len() <= limit <= MAX_ANY_FRAME, which fits in u32.
    dst.put_u32(u32::try_from(body.len()).map_err(|_| ProtocolError::Encode)?);
    dst.put_slice(&body);
    Ok(())
}

/// Serialize `message` into a standalone frame.
///
/// # Errors
/// See [`encode`].
pub fn encode_to_vec<T: Serialize>(channel: Channel, message: &T) -> Result<Vec<u8>> {
    let mut buf = BytesMut::new();
    encode(channel, message, &mut buf)?;
    Ok(buf.to_vec())
}

/// A decoded frame: which channel it arrived on and its raw body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Channel the frame was sent on.
    pub channel: Channel,
    /// Undecoded body bytes.
    pub body: Vec<u8>,
}

impl Frame {
    /// Deserialize the body into `T`.
    ///
    /// # Errors
    /// Returns [`ProtocolError::MalformedBody`] if the bytes do not describe a `T`.
    pub fn decode_body<T: DeserializeOwned>(&self) -> Result<T> {
        postcard::from_bytes(&self.body).map_err(|_| ProtocolError::MalformedBody)
    }
}

/// Incremental frame decoder for a byte stream.
///
/// Feed bytes in with [`FrameDecoder::decode`]; it returns `Ok(None)` while a frame is
/// still incomplete and consumes exactly one frame per `Ok(Some(_))`.
#[derive(Debug, Default, Clone, Copy)]
pub struct FrameDecoder {
    /// Overrides the per-channel limit with something smaller, if set.
    negotiated_limit: Option<usize>,
}

impl FrameDecoder {
    /// A decoder using each channel's default limit.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            negotiated_limit: None,
        }
    }

    /// A decoder capped at `limit` bytes, or the channel default if that is smaller.
    #[must_use]
    pub const fn with_limit(limit: usize) -> Self {
        Self {
            negotiated_limit: Some(limit),
        }
    }

    fn effective_limit(self, channel: Channel) -> usize {
        match self.negotiated_limit {
            Some(l) => l.min(channel.max_frame_len()),
            None => channel.max_frame_len(),
        }
    }

    /// Try to pull one frame from the front of `src`.
    ///
    /// On success the frame's bytes are removed from `src`. On error `src` is left
    /// untouched; the caller should treat any error as fatal for the connection, since
    /// the stream can no longer be resynchronised.
    ///
    /// # Errors
    /// Returns an error for bad magic, unknown channels, empty bodies, or bodies that
    /// exceed the effective limit.
    pub fn decode(self, src: &mut BytesMut) -> Result<Option<Frame>> {
        if src.len() < HEADER_LEN {
            return Ok(None);
        }

        if src[0..2] != MAGIC {
            return Err(ProtocolError::BadMagic);
        }
        let channel = Channel::from_wire(src[2])?;

        let len = u32::from_be_bytes([src[3], src[4], src[5], src[6]]) as usize;
        if len == 0 {
            return Err(ProtocolError::EmptyFrame);
        }
        let limit = self.effective_limit(channel);
        if len > limit {
            // Rejected before allocating anything.
            return Err(ProtocolError::FrameTooLarge { actual: len, limit });
        }

        if src.len() < HEADER_LEN + len {
            // Hint the allocator now that we know the length is sane.
            src.reserve(HEADER_LEN + len - src.len());
            return Ok(None);
        }

        src.advance(HEADER_LEN);
        let body = src.split_to(len).to_vec();
        Ok(Some(Frame { channel, body }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct Sample {
        n: u32,
        s: String,
    }

    fn sample() -> Sample {
        Sample {
            n: 42,
            s: "hello".into(),
        }
    }

    #[test]
    fn encode_then_decode_roundtrips() {
        let mut buf = BytesMut::new();
        encode(Channel::Control, &sample(), &mut buf).unwrap();

        let frame = FrameDecoder::new().decode(&mut buf).unwrap().unwrap();
        assert_eq!(frame.channel, Channel::Control);
        assert_eq!(frame.decode_body::<Sample>().unwrap(), sample());
        assert!(buf.is_empty(), "decoder must consume exactly one frame");
    }

    #[test]
    fn decodes_two_frames_from_one_buffer() {
        let mut buf = BytesMut::new();
        encode(Channel::Control, &sample(), &mut buf).unwrap();
        encode(Channel::FileTransfer, &sample(), &mut buf).unwrap();

        let d = FrameDecoder::new();
        assert_eq!(
            d.decode(&mut buf).unwrap().unwrap().channel,
            Channel::Control
        );
        assert_eq!(
            d.decode(&mut buf).unwrap().unwrap().channel,
            Channel::FileTransfer
        );
        assert!(d.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn partial_frames_yield_none_until_complete() {
        let full = encode_to_vec(Channel::Control, &sample()).unwrap();
        let d = FrameDecoder::new();
        let mut buf = BytesMut::new();

        for byte in &full[..full.len() - 1] {
            buf.put_u8(*byte);
            assert!(
                d.decode(&mut buf).unwrap().is_none(),
                "incomplete frame must not decode"
            );
        }
        buf.put_u8(full[full.len() - 1]);
        assert!(d.decode(&mut buf).unwrap().is_some());
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = BytesMut::from(&b"XX\x01\x00\x00\x00\x01A"[..]);
        assert!(matches!(
            FrameDecoder::new().decode(&mut buf),
            Err(ProtocolError::BadMagic)
        ));
    }

    #[test]
    fn rejects_unknown_channel() {
        let mut buf = BytesMut::new();
        buf.put_slice(&MAGIC);
        buf.put_u8(200);
        buf.put_u32(1);
        buf.put_u8(b'A');
        assert!(matches!(
            FrameDecoder::new().decode(&mut buf),
            Err(ProtocolError::UnknownChannel(200))
        ));
    }

    #[test]
    fn rejects_zero_length_body() {
        let mut buf = BytesMut::new();
        buf.put_slice(&MAGIC);
        buf.put_u8(Channel::Control.to_wire());
        buf.put_u32(0);
        assert!(matches!(
            FrameDecoder::new().decode(&mut buf),
            Err(ProtocolError::EmptyFrame)
        ));
    }

    #[test]
    fn rejects_oversized_declared_length_without_allocating() {
        // Header claims 4 GiB - 1 on the control channel. Only 7 bytes are supplied.
        let mut buf = BytesMut::new();
        buf.put_slice(&MAGIC);
        buf.put_u8(Channel::Control.to_wire());
        buf.put_u32(u32::MAX);
        let err = FrameDecoder::new().decode(&mut buf).unwrap_err();
        assert!(matches!(err, ProtocolError::FrameTooLarge { .. }));
    }

    #[test]
    fn negotiated_limit_can_only_tighten() {
        let d = FrameDecoder::with_limit(16);
        assert_eq!(d.effective_limit(Channel::Video), 16);

        let d = FrameDecoder::with_limit(usize::MAX);
        assert_eq!(
            d.effective_limit(Channel::Input),
            Channel::Input.max_frame_len()
        );
    }

    #[test]
    fn encode_rejects_bodies_over_the_channel_limit() {
        let big = vec![0u8; Channel::Input.max_frame_len() + 1];
        let err = encode(Channel::Input, &big, &mut BytesMut::new()).unwrap_err();
        assert!(matches!(err, ProtocolError::FrameTooLarge { .. }));
    }

    #[test]
    fn decoding_wrong_type_is_a_malformed_body_not_a_panic() {
        let frame = Frame {
            channel: Channel::Control,
            body: vec![0xff, 0xff, 0xff],
        };
        assert!(matches!(
            frame.decode_body::<Sample>(),
            Err(ProtocolError::MalformedBody)
        ));
    }

    #[test]
    fn channel_wire_bytes_roundtrip() {
        for ch in [
            Channel::Control,
            Channel::FileTransfer,
            Channel::Video,
            Channel::Input,
            Channel::Metrics,
        ] {
            assert_eq!(Channel::from_wire(ch.to_wire()).unwrap(), ch);
        }
    }
}
