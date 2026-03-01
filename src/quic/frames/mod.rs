#![allow(dead_code)]
use bytes::Bytes;
use thiserror::Error;

use crate::quic::decode::var_int;

type VarInt = u64;

#[derive(Error, Debug, PartialEq)]
pub enum FrameError {
    #[error("Buffer too short")]
    BufferTooShort,
    #[error("Invalid frame type")]
    InvalidFrameType,
    #[error("Invalid variable length integer decoding")]
    InvalidVarInt,
    #[error("Invalid connection id length")]
    InvalidConnectionIdLength,
}

#[derive(Debug, PartialEq)]
pub enum StreamDirection {
    BiDirectional,
    UniDirectional,
}

#[derive(Debug, PartialEq)]
pub enum Frame {
    Padding,
    Ping,
    HandshakeDone,
    MaxData(VarInt),
    DataBlocked(VarInt),
    RetireConnectionId(VarInt),
    ResetStream(VarInt, VarInt, VarInt),
    StopSending(VarInt, VarInt),
    MaxStreamData(VarInt, VarInt),
    MaxStreams(StreamDirection, VarInt),
    StreamDataBlocked(VarInt, VarInt),
    StreamsBlocked(StreamDirection, VarInt),
    PathChallenge([u8; 8]),
    PathResponse([u8; 8]),
    NewToken(VarInt, Bytes),
    Crypto(VarInt, VarInt, Bytes),
    NewConnectionId(VarInt, VarInt, u8, VarInt, u128),
    ConnectionClose(VarInt, Option<VarInt>, VarInt, Bytes),
}

impl Frame {
    pub fn decode(buf: &mut Bytes) -> Result<Self, FrameError> {
        if buf.is_empty() {
            return Err(FrameError::BufferTooShort);
        }

        let frame_type = var_int::read(buf).ok_or(FrameError::InvalidVarInt)?;

        match frame_type {
            0x00 => Ok(Frame::Padding),
            0x01 => Ok(Frame::Ping),
            0x10 => {
                if buf.is_empty() {
                    return Err(FrameError::InvalidVarInt);
                }
                let maximum_data = var_int::read(buf).ok_or(FrameError::InvalidVarInt)?;
                Ok(Frame::MaxData(maximum_data))
            }
            0x1e => Ok(Frame::HandshakeDone),
            _ => Err(FrameError::InvalidFrameType),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_returns_buffer_too_short_on_empty_input() {
        let mut buf = Bytes::new();
        assert_eq!(Frame::decode(&mut buf), Err(FrameError::BufferTooShort));
    }

    #[test]
    fn test_decode_padding_frame() {
        let mut buf = Bytes::from_static(&[0x00]);
        assert_eq!(Frame::decode(&mut buf), Ok(Frame::Padding));
    }

    #[test]
    fn test_decode_ping_frame() {
        let mut buf = Bytes::from_static(&[0x01]);
        assert_eq!(Frame::decode(&mut buf), Ok(Frame::Ping));
    }

    #[test]
    fn test_decode_handshake_done_frame() {
        let mut buf = Bytes::from_static(&[0x1e]);
        assert_eq!(Frame::decode(&mut buf), Ok(Frame::HandshakeDone));
    }

    #[test]
    fn test_decode_max_data_frame() {
        // Type 0x10, maximum_data=42
        let mut buf = Bytes::from_static(&[0x10, 0x2a]);
        assert_eq!(Frame::decode(&mut buf), Ok(Frame::MaxData(42)));
    }

    #[test]
    fn test_decode_max_data_frame_buffer_too_short() {
        // Type 0x10, missing maximum_data field
        let mut buf = Bytes::from_static(&[0x10]);
        assert_eq!(Frame::decode(&mut buf), Err(FrameError::InvalidVarInt));
    }
}
