#![allow(dead_code)]
use bytes::{Buf, Bytes};
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
            0x14 => {
                if buf.is_empty() {
                    return Err(FrameError::InvalidVarInt);
                }
                let maximum_data = var_int::read(buf).ok_or(FrameError::InvalidVarInt)?;
                Ok(Frame::DataBlocked(maximum_data))
            }
            0x19 => {
                if buf.is_empty() {
                    return Err(FrameError::InvalidVarInt);
                }
                let sequence_number = var_int::read(buf).ok_or(FrameError::InvalidVarInt)?;
                Ok(Frame::RetireConnectionId(sequence_number))
            }
            0x1a => {
                if buf.remaining() < 8 {
                    return Err(FrameError::BufferTooShort);
                }
                let mut data = [0u8; 8];
                for i in &mut data {
                    *i = buf.get_u8();
                }
                Ok(Frame::PathChallenge(data))
            }
            0x1b => {
                if buf.remaining() < 8 {
                    return Err(FrameError::BufferTooShort);
                }
                let mut data = [0u8; 8];
                for i in &mut data {
                    *i = buf.get_u8();
                }
                Ok(Frame::PathResponse(data))
            }
            0x1c => {
                let error_code = var_int::read(buf).ok_or(FrameError::InvalidVarInt)?;
                let frame_type = var_int::read(buf).ok_or(FrameError::InvalidVarInt)?;
                let reason_phrase_length =
                    var_int::read(buf).ok_or(FrameError::InvalidVarInt)? as usize;
                if buf.remaining() < reason_phrase_length {
                    return Err(FrameError::BufferTooShort);
                }
                let reason_phrase = buf.split_to(reason_phrase_length);
                Ok(Frame::ConnectionClose(
                    error_code,
                    Some(frame_type),
                    reason_phrase_length as VarInt,
                    reason_phrase,
                ))
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
    fn test_decode_path_challenge() {
        let mut buf =
            Bytes::from_static(&[0x1a, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(
            Frame::decode(&mut buf),
            Ok(Frame::PathChallenge([
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
            ]))
        );
    }

    #[test]
    fn test_decode_path_challenge_buffer_too_short() {
        let mut buf = Bytes::from_static(&[0x1a, 0x01, 0x02]);
        assert_eq!(
            Frame::decode(&mut buf),
            Err(FrameError::BufferTooShort)
        );
    }

    #[test]
    fn test_decode_path_response() {
        let mut buf =
            Bytes::from_static(&[0x1b, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(
            Frame::decode(&mut buf),
            Ok(Frame::PathResponse([
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
            ]))
        );
    }

    #[test]
    fn test_decode_path_response_buffer_too_short() {
        let mut buf = Bytes::from_static(&[0x1b, 0x01, 0x02]);
        assert_eq!(
            Frame::decode(&mut buf),
            Err(FrameError::BufferTooShort)
        );
    }

    #[test]
    fn test_decode_connection_close_quic_empty_reason() {
        // Type 0x1c, error_code=0x00, frame_type=0x00, reason_phrase_length=0
        let mut buf = Bytes::from_static(&[0x1c, 0x00, 0x00, 0x00]);
        assert_eq!(
            Frame::decode(&mut buf),
            Ok(Frame::ConnectionClose(
                0x00,
                Some(0x00),
                0,
                Bytes::new()
            ))
        );
    }

    #[test]
    fn test_decode_connection_close_quic_with_reason() {
        // Type 0x1c, error_code=0x0a, frame_type=0x01, reason_phrase_length=5, reason="error"
        let mut buf =
            Bytes::from_static(&[0x1c, 0x0a, 0x01, 0x05, b'e', b'r', b'r', b'o', b'r']);
        assert_eq!(
            Frame::decode(&mut buf),
            Ok(Frame::ConnectionClose(
                0x0a,
                Some(0x01),
                5,
                Bytes::from_static(b"error")
            ))
        );
    }

    #[test]
    fn test_decode_connection_close_quic_buffer_too_short() {
        // Type 0x1c, error_code=0x0a, frame_type=0x01, reason_phrase_length=5, but only 2 bytes of reason
        let mut buf = Bytes::from_static(&[0x1c, 0x0a, 0x01, 0x05, b'e', b'r']);
        assert_eq!(
            Frame::decode(&mut buf),
            Err(FrameError::BufferTooShort)
        );
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

    #[test]
    fn test_decode_data_blocked_frame() {
        // Type 0x14, maximum_data=63
        let mut buf = Bytes::from_static(&[0x14, 0x3f]);
        assert_eq!(Frame::decode(&mut buf), Ok(Frame::DataBlocked(63)));
    }

    #[test]
    fn test_decode_data_blocked_frame_buffer_too_short() {
        // Type 0x14, missing maximum_data field
        let mut buf = Bytes::from_static(&[0x14]);
        assert_eq!(Frame::decode(&mut buf), Err(FrameError::InvalidVarInt));
    }

    #[test]
    fn test_decode_retire_connection_id_frame() {
        // Type 0x19, sequence_number=5
        let mut buf = Bytes::from_static(&[0x19, 0x05]);
        assert_eq!(Frame::decode(&mut buf), Ok(Frame::RetireConnectionId(5)));
    }

    #[test]
    fn test_decode_retire_connection_id_frame_buffer_too_short() {
        // Type 0x19, missing sequence_number field
        let mut buf = Bytes::from_static(&[0x19]);
        assert_eq!(Frame::decode(&mut buf), Err(FrameError::InvalidVarInt));
    }
}
