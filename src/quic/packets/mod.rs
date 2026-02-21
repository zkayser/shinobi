#![allow(dead_code)]
use bytes::Bytes;
use thiserror::Error;

pub mod long_header;
pub mod short_header;
pub mod version_negotation;

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

pub trait Decode: Sized {
    fn decode(buf: Bytes) -> Result<Self, PacketError>;
}
