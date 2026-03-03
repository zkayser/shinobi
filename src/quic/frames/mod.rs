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
            0x06 => {
                if buf.remaining() == 0 {
                    return Err(FrameError::InvalidVarInt);
                }
                let offset = var_int::read(buf).ok_or(FrameError::InvalidVarInt)?;
                if buf.remaining() == 0 {
                    return Err(FrameError::InvalidVarInt);
                }
                let length = var_int::read(buf).ok_or(FrameError::InvalidVarInt)?;
                if buf.remaining() < length as usize {
                    return Err(FrameError::BufferTooShort);
                }
                let crypto_data = buf.copy_to_bytes(length as usize);
                Ok(Frame::Crypto(offset, length, crypto_data))
            }
            0x07 => {
                if buf.remaining() == 0 {
                    return Err(FrameError::InvalidVarInt);
                }
                let token_length = var_int::read(buf).ok_or(FrameError::InvalidVarInt)?;
                if buf.remaining() < token_length as usize {
                    return Err(FrameError::BufferTooShort);
                }
                let token = buf.copy_to_bytes(token_length as usize);
                Ok(Frame::NewToken(token_length, token))
            }
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
            0x18 => {
                if buf.remaining() == 0 {
                    return Err(FrameError::InvalidVarInt);
                }
                let sequence_number = var_int::read(buf).ok_or(FrameError::InvalidVarInt)?;
                if buf.remaining() == 0 {
                    return Err(FrameError::InvalidVarInt);
                }
                let retire_prior_to = var_int::read(buf).ok_or(FrameError::InvalidVarInt)?;
                if buf.remaining() == 0 {
                    return Err(FrameError::BufferTooShort);
                }
                let connection_id_length = buf[0];
                buf.advance(1);
                if connection_id_length > 8 {
                    return Err(FrameError::InvalidConnectionIdLength);
                }
                if buf.remaining() < connection_id_length as usize {
                    return Err(FrameError::BufferTooShort);
                }
                let connection_id = if connection_id_length > 0 {
                    let cid_bytes = buf.copy_to_bytes(connection_id_length as usize);
                    let mut padded = [0u8; 8];
                    let start = 8 - connection_id_length as usize;
                    padded[start..].copy_from_slice(&cid_bytes);
                    u64::from_be_bytes(padded)
                } else {
                    0
                };
                if buf.remaining() < 16 {
                    return Err(FrameError::BufferTooShort);
                }
                let stateless_reset_token = u128::from_be_bytes([
                    buf[0], buf[1], buf[2], buf[3],
                    buf[4], buf[5], buf[6], buf[7],
                    buf[8], buf[9], buf[10], buf[11],
                    buf[12], buf[13], buf[14], buf[15],
                ]);
                buf.advance(16);
                Ok(Frame::NewConnectionId(sequence_number, retire_prior_to, connection_id_length, connection_id, stateless_reset_token))
            }
            0x19 => {
                if buf.is_empty() {
                    return Err(FrameError::InvalidVarInt);
                }
                let sequence_number = var_int::read(buf).ok_or(FrameError::InvalidVarInt)?;
                Ok(Frame::RetireConnectionId(sequence_number))
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
    fn test_decode_crypto_frame() {
        let mut buf = Bytes::from_static(&[0x06, 0x00, 0x03, b'T', b'L', b'S']);
        assert_eq!(Frame::decode(&mut buf), Ok(Frame::Crypto(0, 3, Bytes::from_static(&[b'T', b'L', b'S']))));
    }

    #[test]
    fn test_decode_crypto_frame_with_nonzero_offset() {
        let mut buf = Bytes::from_static(&[0x06, 0x0a, 0x02, b'H', b'i']);
        assert_eq!(Frame::decode(&mut buf), Ok(Frame::Crypto(10, 2, Bytes::from_static(&[b'H', b'i']))));
    }

    #[test]
    fn test_decode_crypto_frame_buffer_too_short() {
        let mut buf = Bytes::from_static(&[0x06, 0x00, 0x05, b'T', b'L']);
        assert_eq!(Frame::decode(&mut buf), Err(FrameError::BufferTooShort));
    }

    #[test]
    fn test_decode_crypto_frame_missing_length() {
        let mut buf = Bytes::from_static(&[0x06, 0x00]);
        assert_eq!(Frame::decode(&mut buf), Err(FrameError::InvalidVarInt));
    }

    #[test]
    fn test_decode_new_token_frame() {
        let mut buf = Bytes::from_static(&[0x07, 0x03, b'a', b'b', b'c']);
        assert_eq!(Frame::decode(&mut buf), Ok(Frame::NewToken(3, Bytes::from_static(&[b'a', b'b', b'c']))));
    }

    #[test]
    fn test_decode_new_token_frame_empty_token() {
        let mut buf = Bytes::from_static(&[0x07, 0x00]);
        assert_eq!(Frame::decode(&mut buf), Ok(Frame::NewToken(0, Bytes::from_static(&[]))));
    }

    #[test]
    fn test_decode_new_token_frame_buffer_too_short() {
        let mut buf = Bytes::from_static(&[0x07, 0x05, b'a', b'b']);
        assert_eq!(Frame::decode(&mut buf), Err(FrameError::BufferTooShort));
    }

    #[test]
    fn test_decode_new_token_frame_missing_length() {
        let mut buf = Bytes::from_static(&[0x07]);
        assert_eq!(Frame::decode(&mut buf), Err(FrameError::InvalidVarInt));
    }

    #[test]
    fn test_decode_new_connection_id_frame() {
        let mut buf = Bytes::from_static(&[
            0x18, // frame type
            0x01, // sequence_number = 1
            0x00, // retire_prior_to = 0
            0x04, // connection_id_length = 4
            0xDE, 0xAD, 0xBE, 0xEF, // connection_id
            // stateless_reset_token (16 bytes)
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ]);
        let expected_cid: u64 = 0xDEADBEEF;
        let expected_token: u128 = 0x000102030405060708090a0b0c0d0e0f;
        assert_eq!(
            Frame::decode(&mut buf),
            Ok(Frame::NewConnectionId(1, 0, 4, expected_cid, expected_token))
        );
    }

    #[test]
    fn test_decode_new_connection_id_frame_zero_length_cid() {
        let mut buf = Bytes::from_static(&[
            0x18, // frame type
            0x02, // sequence_number = 2
            0x01, // retire_prior_to = 1
            0x00, // connection_id_length = 0
            // stateless_reset_token (16 bytes)
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ]);
        let expected_token: u128 = 0x101112131415161718191a1b1c1d1e1f;
        assert_eq!(
            Frame::decode(&mut buf),
            Ok(Frame::NewConnectionId(2, 1, 0, 0, expected_token))
        );
    }

    #[test]
    fn test_decode_new_connection_id_frame_invalid_cid_length() {
        let mut buf = Bytes::from_static(&[
            0x18, // frame type
            0x01, // sequence_number
            0x00, // retire_prior_to
            0x09, // connection_id_length = 9 (> 8, invalid)
        ]);
        assert_eq!(Frame::decode(&mut buf), Err(FrameError::InvalidConnectionIdLength));
    }

    #[test]
    fn test_decode_new_connection_id_frame_buffer_too_short_for_token() {
        let mut buf = Bytes::from_static(&[
            0x18, // frame type
            0x01, // sequence_number
            0x00, // retire_prior_to
            0x02, // connection_id_length = 2
            0xAB, 0xCD, // connection_id
            // only 4 bytes of reset token (need 16)
            0x00, 0x01, 0x02, 0x03,
        ]);
        assert_eq!(Frame::decode(&mut buf), Err(FrameError::BufferTooShort));
    }

    #[test]
    fn test_decode_new_connection_id_frame_missing_fields() {
        let mut buf = Bytes::from_static(&[0x18]);
        assert_eq!(Frame::decode(&mut buf), Err(FrameError::InvalidVarInt));
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
