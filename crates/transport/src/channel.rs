//! Protocol frames over QUIC streams.
//!
//! # One stream per channel
//!
//! Each [`Channel`] is carried on its own bidirectional QUIC stream. QUIC delivers each
//! stream independently, so a multi-gigabyte file transfer on
//! [`Channel::FileTransfer`] cannot delay a keystroke on [`Channel::Input`]. Running
//! everything over one stream would reintroduce exactly the head-of-line blocking QUIC
//! exists to avoid.
//!
//! The first thing written on a new stream is a single byte naming its channel, so the
//! accepting side knows what it is before reading any frame.
//!
//! # Reading is bounded everywhere
//!
//! [`ChannelReader`] enforces the channel's frame ceiling from the 7-byte header,
//! before allocating for the body, and additionally caps how much unparsed data it will
//! buffer. A peer that sends a valid header and then stalls cannot make the reader hold
//! memory indefinitely, and one that sends an oversized length is rejected without the
//! allocation ever happening.

use bytes::BytesMut;
use quinn::{RecvStream, SendStream};
use rc_protocol::frame::{self, Channel, Frame, FrameDecoder};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::{Result, TransportError};

/// Largest amount of not-yet-parsed data held per stream.
///
/// A frame is rejected on its header if it exceeds the channel limit, so this only ever
/// holds one in-flight frame plus a partial next one. The factor of two gives room for
/// that without letting a stalled peer grow the buffer.
const READ_BUFFER_CEILING_FACTOR: usize = 2;

/// How many bytes to request from QUIC per read.
const READ_CHUNK: usize = 16 * 1024;

/// Writes frames to one channel's stream.
#[derive(Debug)]
pub struct ChannelWriter {
    channel: Channel,
    stream: SendStream,
}

impl ChannelWriter {
    /// Open a new stream on `connection` and announce its channel.
    ///
    /// # Errors
    /// [`TransportError::Stream`] if the stream cannot be opened or the header written.
    pub async fn open(connection: &quinn::Connection, channel: Channel) -> Result<Self> {
        let mut stream = connection
            .open_bi()
            .await
            .map(|(send, _recv)| send)
            .map_err(|err| TransportError::Stream {
                channel: channel_name(channel),
                reason: err.to_string(),
            })?;

        // The channel byte precedes every frame on this stream.
        stream
            .write_all(&[channel.to_wire()])
            .await
            .map_err(|err| TransportError::Stream {
                channel: channel_name(channel),
                reason: err.to_string(),
            })?;

        Ok(Self { channel, stream })
    }

    /// Wrap an already-opened stream whose channel byte has been written.
    #[must_use]
    pub const fn from_stream(channel: Channel, stream: SendStream) -> Self {
        Self { channel, stream }
    }

    /// Which channel this writer serves.
    #[must_use]
    pub const fn channel(&self) -> Channel {
        self.channel
    }

    /// Encode and send one message.
    ///
    /// # Errors
    /// [`TransportError::Protocol`] if the message exceeds the channel's frame limit —
    /// caught here rather than at the peer, so an oversized frame is a local bug rather
    /// than a dropped connection. [`TransportError::Stream`] if the write fails.
    pub async fn send<T: Serialize>(&mut self, message: &T) -> Result<()> {
        let mut buf = BytesMut::new();
        frame::encode(self.channel, message, &mut buf)?;

        self.stream
            .write_all(&buf)
            .await
            .map_err(|err| TransportError::Stream {
                channel: channel_name(self.channel),
                reason: err.to_string(),
            })
    }

    /// Finish the stream cleanly, signalling no more frames.
    ///
    /// # Errors
    /// [`TransportError::Stream`] if the stream cannot be finished.
    pub fn finish(&mut self) -> Result<()> {
        self.stream.finish().map_err(|err| TransportError::Stream {
            channel: channel_name(self.channel),
            reason: err.to_string(),
        })
    }
}

/// Reads frames from one channel's stream.
#[derive(Debug)]
pub struct ChannelReader {
    channel: Channel,
    stream: RecvStream,
    buffer: BytesMut,
    decoder: FrameDecoder,
}

impl ChannelReader {
    /// Wrap a stream whose channel byte has already been consumed.
    #[must_use]
    pub fn from_stream(channel: Channel, stream: RecvStream) -> Self {
        Self {
            channel,
            stream,
            buffer: BytesMut::new(),
            decoder: FrameDecoder::new(),
        }
    }

    /// Read the leading channel byte from an accepted stream, then wrap it.
    ///
    /// # Errors
    /// [`TransportError::Stream`] if the byte cannot be read, or
    /// [`TransportError::Protocol`] if it names no known channel.
    pub async fn accept(mut stream: RecvStream) -> Result<Self> {
        let mut header = [0u8; 1];
        stream
            .read_exact(&mut header)
            .await
            .map_err(|err| TransportError::Stream {
                channel: "unknown",
                reason: err.to_string(),
            })?;

        let channel = Channel::from_wire(header[0])?;
        Ok(Self::from_stream(channel, stream))
    }

    /// Which channel this reader serves.
    #[must_use]
    pub const fn channel(&self) -> Channel {
        self.channel
    }

    /// Read the next frame, or `None` when the peer finished the stream.
    ///
    /// # Errors
    /// [`TransportError::Protocol`] for a malformed or oversized frame,
    /// [`TransportError::Stream`] for a read failure.
    pub async fn next_frame(&mut self) -> Result<Option<Frame>> {
        loop {
            // Anything already buffered may already hold a complete frame.
            if let Some(frame) = self.decoder.decode(&mut self.buffer)? {
                return Ok(Some(frame));
            }

            let ceiling = self.channel.max_frame_len() * READ_BUFFER_CEILING_FACTOR;
            if self.buffer.len() > ceiling {
                // Unreachable while the decoder rejects oversized frames on their
                // header, but asserted anyway: this is the invariant that stops a
                // stalled peer from growing the buffer without bound.
                return Err(TransportError::Protocol(
                    rc_protocol::ProtocolError::FrameTooLarge {
                        actual: self.buffer.len(),
                        limit: ceiling,
                    },
                ));
            }

            let chunk = self
                .stream
                .read_chunk(READ_CHUNK, true)
                .await
                .map_err(|err| TransportError::Stream {
                    channel: channel_name(self.channel),
                    reason: err.to_string(),
                })?;

            match chunk {
                Some(chunk) => self.buffer.extend_from_slice(&chunk.bytes),
                None => {
                    // Clean end of stream. Trailing bytes mean a truncated frame, which
                    // is an error rather than a quiet end.
                    return if self.buffer.is_empty() {
                        Ok(None)
                    } else {
                        Err(TransportError::Protocol(
                            rc_protocol::ProtocolError::MalformedBody,
                        ))
                    };
                }
            }
        }
    }

    /// Read the next frame and decode its body.
    ///
    /// # Errors
    /// As [`ChannelReader::next_frame`], plus [`TransportError::Protocol`] if the body
    /// does not describe a `T`.
    pub async fn next_message<T: DeserializeOwned>(&mut self) -> Result<Option<T>> {
        match self.next_frame().await? {
            Some(frame) => Ok(Some(frame.decode_body()?)),
            None => Ok(None),
        }
    }
}

/// Open a channel and get both halves of it.
///
/// A channel is one **bidirectional** QUIC stream. The side that opens it writes the
/// one-byte channel tag; replies come back on the same stream and carry no tag, because
/// the channel is already established. Opening a second stream for the reply direction
/// would leave both peers waiting for each other.
///
/// # Errors
/// [`TransportError::Stream`] if the stream cannot be opened or tagged.
pub async fn open_channel(
    connection: &quinn::Connection,
    channel: Channel,
) -> Result<(ChannelWriter, ChannelReader)> {
    let (mut send, recv) = connection
        .open_bi()
        .await
        .map_err(|err| TransportError::Stream {
            channel: channel_name(channel),
            reason: err.to_string(),
        })?;

    send.write_all(&[channel.to_wire()])
        .await
        .map_err(|err| TransportError::Stream {
            channel: channel_name(channel),
            reason: err.to_string(),
        })?;

    Ok((
        ChannelWriter::from_stream(channel, send),
        // No tag to consume: this half carries the peer's replies on an
        // already-identified stream.
        ChannelReader::from_stream(channel, recv),
    ))
}

/// Accept a channel the peer opened, reading its tag.
///
/// # Errors
/// [`TransportError::Stream`] if the stream cannot be accepted, or
/// [`TransportError::Protocol`] if the tag names no known channel.
pub async fn accept_channel(
    connection: &quinn::Connection,
) -> Result<(ChannelWriter, ChannelReader)> {
    let (send, recv) = connection
        .accept_bi()
        .await
        .map_err(|err| TransportError::Stream {
            channel: "unknown",
            reason: err.to_string(),
        })?;

    let reader = ChannelReader::accept(recv).await?;
    let channel = reader.channel();

    Ok((ChannelWriter::from_stream(channel, send), reader))
}

/// Stable name for a channel, for error messages and logs.
const fn channel_name(channel: Channel) -> &'static str {
    match channel {
        Channel::Control => "control",
        Channel::FileTransfer => "file-transfer",
        Channel::Video => "video",
        Channel::Input => "input",
        Channel::Metrics => "metrics",
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use rc_security::{DeviceIdentity, SystemClock};
    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::endpoint::{AgentListener, ClientConnector};
    use crate::tls::PinPolicy;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Ping {
        sequence: u32,
        note: String,
    }

    /// A connected agent/client pair over loopback.
    struct Link {
        agent: quinn::Connection,
        client: quinn::Connection,
        _listener: AgentListener,
        _connector: ClientConnector,
    }

    async fn connected() -> Link {
        let agent_id = DeviceIdentity::generate("agent", &SystemClock).unwrap();
        let client_id = DeviceIdentity::generate("client", &SystemClock).unwrap();

        let (listener, _) = AgentListener::bind(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &agent_id,
            PinPolicy::Pinned(client_id.public().certificate_fingerprint),
        )
        .unwrap();
        let address = listener.local_address().unwrap();

        let (connector, _) = ClientConnector::new(
            &client_id,
            PinPolicy::Pinned(agent_id.public().certificate_fingerprint),
        )
        .unwrap();

        let (accepted, connected) = tokio::join!(listener.accept(), connector.connect(address));

        Link {
            agent: accepted.unwrap().unwrap(),
            client: connected.unwrap(),
            _listener: listener,
            _connector: connector,
        }
    }

    #[tokio::test]
    async fn a_message_round_trips_over_a_channel() {
        let link = connected().await;

        let mut writer = ChannelWriter::open(&link.client, Channel::Control)
            .await
            .unwrap();

        let sent = Ping {
            sequence: 7,
            note: "hello".to_owned(),
        };
        writer.send(&sent).await.unwrap();

        let (_send, recv) = link.agent.accept_bi().await.unwrap();
        let mut reader = ChannelReader::accept(recv).await.unwrap();

        assert_eq!(reader.channel(), Channel::Control);
        let received: Ping = reader.next_message().await.unwrap().unwrap();
        assert_eq!(received, sent);
    }

    #[tokio::test]
    async fn frames_arrive_in_order_and_the_stream_ends_cleanly() {
        let link = connected().await;

        let mut writer = ChannelWriter::open(&link.client, Channel::Control)
            .await
            .unwrap();
        for sequence in 0..16 {
            writer
                .send(&Ping {
                    sequence,
                    note: format!("n{sequence}"),
                })
                .await
                .unwrap();
        }
        writer.finish().unwrap();

        let (_send, recv) = link.agent.accept_bi().await.unwrap();
        let mut reader = ChannelReader::accept(recv).await.unwrap();

        for expected in 0..16 {
            let ping: Ping = reader.next_message().await.unwrap().unwrap();
            assert_eq!(ping.sequence, expected, "frames must stay in order");
        }

        assert!(
            reader.next_message::<Ping>().await.unwrap().is_none(),
            "a finished stream reads as end-of-stream, not an error"
        );
    }

    #[tokio::test]
    async fn each_channel_is_carried_on_its_own_stream() {
        let link = connected().await;

        // Open two channels and interleave: each must arrive on its own stream with its
        // own channel tag.
        let mut control = ChannelWriter::open(&link.client, Channel::Control)
            .await
            .unwrap();
        let mut input = ChannelWriter::open(&link.client, Channel::Input)
            .await
            .unwrap();

        control
            .send(&Ping {
                sequence: 1,
                note: "control".to_owned(),
            })
            .await
            .unwrap();
        input
            .send(&Ping {
                sequence: 2,
                note: "input".to_owned(),
            })
            .await
            .unwrap();

        let mut seen = Vec::new();
        for _ in 0..2 {
            let (_send, recv) = link.agent.accept_bi().await.unwrap();
            let mut reader = ChannelReader::accept(recv).await.unwrap();
            let ping: Ping = reader.next_message().await.unwrap().unwrap();
            seen.push((reader.channel(), ping.note));
        }

        seen.sort_by_key(|(_, note)| note.clone());
        assert_eq!(
            seen,
            vec![
                (Channel::Control, "control".to_owned()),
                (Channel::Input, "input".to_owned()),
            ]
        );
    }

    #[tokio::test]
    async fn a_frame_over_the_channel_limit_is_refused_before_it_is_sent() {
        let link = connected().await;

        // Input has a deliberately low ceiling so flooding is blunted. A message past
        // it must fail locally rather than killing the connection at the peer.
        let mut input = ChannelWriter::open(&link.client, Channel::Input)
            .await
            .unwrap();

        let oversized = Ping {
            sequence: 1,
            note: "x".repeat(Channel::Input.max_frame_len() + 64),
        };

        let result = input.send(&oversized).await;
        assert!(
            matches!(result, Err(TransportError::Protocol(_))),
            "an oversized frame must be refused locally, got {result:?}"
        );

        // The connection is still usable afterwards.
        input
            .send(&Ping {
                sequence: 2,
                note: "fine".to_owned(),
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_channel_carries_both_directions_on_one_stream() {
        // The reply must come back on the stream the initiator opened. If each side
        // opened its own, both would block waiting for the other.
        let link = connected().await;

        let client_side = async {
            let (mut writer, mut reader) =
                open_channel(&link.client, Channel::Control).await.unwrap();
            writer
                .send(&Ping {
                    sequence: 1,
                    note: "request".to_owned(),
                })
                .await
                .unwrap();
            reader.next_message::<Ping>().await.unwrap().unwrap()
        };

        let agent_side = async {
            let (mut writer, mut reader) = accept_channel(&link.agent).await.unwrap();
            let request: Ping = reader.next_message().await.unwrap().unwrap();
            writer
                .send(&Ping {
                    sequence: request.sequence + 1,
                    note: "reply".to_owned(),
                })
                .await
                .unwrap();
            request
        };

        let (reply, request) = tokio::join!(client_side, agent_side);

        assert_eq!(request.note, "request");
        assert_eq!(reply.note, "reply");
        assert_eq!(reply.sequence, 2, "the reply arrives on the same stream");
    }

    #[tokio::test]
    async fn an_accepted_channel_reports_the_tag_the_initiator_sent() {
        let link = connected().await;

        let opened = async {
            let (mut writer, _reader) = open_channel(&link.client, Channel::Metrics).await.unwrap();
            writer
                .send(&Ping {
                    sequence: 1,
                    note: "m".to_owned(),
                })
                .await
                .unwrap();
        };
        let accepted = async { accept_channel(&link.agent).await.unwrap() };

        let ((), (writer, reader)) = tokio::join!(opened, accepted);

        assert_eq!(reader.channel(), Channel::Metrics);
        assert_eq!(
            writer.channel(),
            Channel::Metrics,
            "the reply writer must inherit the negotiated channel"
        );
    }

    #[tokio::test]
    async fn an_unknown_channel_byte_is_rejected() {
        let link = connected().await;

        let (mut send, _recv) = link.client.open_bi().await.unwrap();
        // 99 is not a channel this build knows.
        send.write_all(&[99]).await.unwrap();
        send.finish().unwrap();

        let (_send, recv) = link.agent.accept_bi().await.unwrap();
        let result = ChannelReader::accept(recv).await;

        assert!(
            matches!(result, Err(TransportError::Protocol(_))),
            "an unknown channel must be refused, got {result:?}"
        );
    }

    #[tokio::test]
    async fn a_truncated_frame_is_an_error_not_a_silent_end() {
        let link = connected().await;

        let (mut send, _recv) = link.client.open_bi().await.unwrap();
        // A valid channel byte and a header promising a body that never arrives.
        send.write_all(&[Channel::Control.to_wire()]).await.unwrap();
        send.write_all(&[0x52, 0x43, Channel::Control.to_wire(), 0, 0, 0, 32])
            .await
            .unwrap();
        send.write_all(b"only a few bytes").await.unwrap();
        send.finish().unwrap();

        let (_send, recv) = link.agent.accept_bi().await.unwrap();
        let mut reader = ChannelReader::accept(recv).await.unwrap();

        let result = reader.next_frame().await;
        assert!(
            result.is_err(),
            "a truncated frame must not read as a clean end, got {result:?}"
        );
    }
}
