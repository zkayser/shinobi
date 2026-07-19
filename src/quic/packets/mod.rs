#![allow(dead_code)]
use bytes::Bytes;
use thiserror::Error;

pub mod long_header;
pub mod short_header;
pub mod version_negotiation;

#[derive(Error, Debug)]
pub enum PacketError {
    #[error("Buffer too short")]
    BufferTooShort,
    #[error("Invalid packet header")]
    InvalidPacketHeader,
    #[error("Invalid variable length integer encoding")]
    InvalidVarInt,
    #[error("Unexpected packet type")]
    UnexpectedPacketType,
}

/// Decode a packet type from a byte buffer.
///
/// Some packet forms need extra connection state to decode. Short-header
/// packets, for example, omit the DCID length from the wire format, so the
/// caller must supply it via [`Self::Context`]. Types that need no extra
/// context use `()` as their context.
pub trait Decode: Sized {
    /// Additional context required for decoding. Use `()` when none is needed.
    type Context;

    fn decode(buf: Bytes, ctx: Self::Context) -> Result<Self, PacketError>;
}
