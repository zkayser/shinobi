#![allow(dead_code)]
use super::{Decode, PacketError};
use crate::quic::decode::var_int;
use bytes::{Buf, Bytes};

#[derive(Debug)]
pub enum LongHeaderPacket {
    Initial {
        version: u32,
        destination_connection_id: Bytes,
        source_connection_id: Bytes,
        token: Bytes,
        packet_number: Bytes,
        packet_payload: Bytes,
    },
    ZeroRtt {
        version: u32,
        destination_connection_id: Bytes,
        source_connection_id: Bytes,
        packet_number: Bytes,
        packet_payload: Bytes,
    },
    Handshake {
        version: u32,
        destination_connection_id: Bytes,
        source_connection_id: Bytes,
        packet_number: Bytes,
        packet_payload: Bytes,
    },
    Retry {
        version: u32,
        destination_connection_id: Bytes,
        source_connection_id: Bytes,
        retry_token: Bytes,
        retry_integrity_tag: Bytes,
    },
}

const LONG_HEADER_FORM: u8 = 0x80;
const FIXED_BIT: u8 = 0x40;
const PACKET_TYPE_MASK: u8 = 0x30;
const PACKET_NUMBER_LENGTH_MASK: u8 = 0x03;

const PACKET_TYPE_INITIAL: u8 = 0x00;
const PACKET_TYPE_ZERO_RTT: u8 = 0x10;
const PACKET_TYPE_HANDSHAKE: u8 = 0x20;
const PACKET_TYPE_RETRY: u8 = 0x30;

const RETRY_INTEGRITY_TAG_LENGTH: usize = 16;

impl Decode for LongHeaderPacket {
    fn decode(mut buf: Bytes) -> Result<Self, PacketError> {
        if buf.is_empty() {
            return Err(PacketError::BufferTooShort);
        }

        let header_byte = buf.get_u8();
        if header_byte & LONG_HEADER_FORM == 0 {
            return Err(PacketError::InvalidPacketHeader);
        }
        if header_byte & FIXED_BIT == 0 {
            return Err(PacketError::InvalidPacketHeader);
        }

        let packet_type = header_byte & PACKET_TYPE_MASK;
        let packet_number_length = (header_byte & PACKET_NUMBER_LENGTH_MASK) + 1;

        if buf.remaining() < 4 {
            return Err(PacketError::BufferTooShort);
        }
        let version = buf.get_u32();

        if buf.remaining() < 1 {
            return Err(PacketError::BufferTooShort);
        }
        let dcid_len = buf.get_u8() as usize;
        if dcid_len > 20 {
            return Err(PacketError::InvalidPacketHeader);
        }
        if buf.remaining() < dcid_len {
            return Err(PacketError::BufferTooShort);
        }
        let destination_connection_id = buf.copy_to_bytes(dcid_len);

        if buf.remaining() < 1 {
            return Err(PacketError::BufferTooShort);
        }
        let scid_len = buf.get_u8() as usize;
        if scid_len > 20 {
            return Err(PacketError::InvalidPacketHeader);
        }
        if buf.remaining() < scid_len {
            return Err(PacketError::BufferTooShort);
        }
        let source_connection_id = buf.copy_to_bytes(scid_len);

        // Retry packets have no length or packet number fields;
        // the remainder is a Retry Token followed by a 16-byte integrity tag.
        if packet_type == PACKET_TYPE_RETRY {
            if buf.remaining() < RETRY_INTEGRITY_TAG_LENGTH {
                return Err(PacketError::BufferTooShort);
            }
            let token_len = buf.remaining() - RETRY_INTEGRITY_TAG_LENGTH;
            let retry_token = buf.copy_to_bytes(token_len);
            let retry_integrity_tag = buf.copy_to_bytes(RETRY_INTEGRITY_TAG_LENGTH);
            return Ok(LongHeaderPacket::Retry {
                version,
                destination_connection_id,
                source_connection_id,
                retry_token,
                retry_integrity_tag,
            });
        }

        // Initial packets have a token field before the length
        let token = if packet_type == PACKET_TYPE_INITIAL {
            let Some(token_length) = var_int::read(&mut buf) else {
                return Err(PacketError::InvalidVarInt);
            };
            if buf.remaining() < token_length as usize {
                return Err(PacketError::BufferTooShort);
            }
            buf.copy_to_bytes(token_length as usize)
        } else {
            Bytes::new()
        };

        let Some(length) = var_int::read(&mut buf) else {
            return Err(PacketError::InvalidVarInt);
        };
        if buf.remaining() < length as usize {
            return Err(PacketError::BufferTooShort);
        }
        if length < packet_number_length as u64 {
            return Err(PacketError::InvalidPacketHeader);
        }

        let mut content = buf.copy_to_bytes(length as usize);
        let packet_number = content.copy_to_bytes(packet_number_length as usize);
        let packet_payload = content;

        match packet_type {
            PACKET_TYPE_INITIAL => Ok(LongHeaderPacket::Initial {
                version,
                destination_connection_id,
                source_connection_id,
                token,
                packet_number,
                packet_payload,
            }),
            PACKET_TYPE_ZERO_RTT => Ok(LongHeaderPacket::ZeroRtt {
                version,
                destination_connection_id,
                source_connection_id,
                packet_number,
                packet_payload,
            }),
            PACKET_TYPE_HANDSHAKE => Ok(LongHeaderPacket::Handshake {
                version,
                destination_connection_id,
                source_connection_id,
                packet_number,
                packet_payload,
            }),
            _ => Err(PacketError::UnexpectedPacketType),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};

    #[test]
    fn test_returns_buffer_too_short_when_buffer_is_empty() {
        let buf = Bytes::from_static(&[]);
        assert!(matches!(
            LongHeaderPacket::decode(buf),
            Err(PacketError::BufferTooShort)
        ));
    }

    #[test]
    fn test_returns_invalid_header_when_not_long_header() {
        let buf = Bytes::from_static(&[0b01000000, 0, 0, 0, 1]);
        assert!(matches!(
            LongHeaderPacket::decode(buf),
            Err(PacketError::InvalidPacketHeader)
        ));
    }

    #[test]
    fn test_returns_invalid_header_when_fixed_bit_not_set() {
        let buf = Bytes::from_static(&[0b10000000, 0, 0, 0, 1]);
        assert!(matches!(
            LongHeaderPacket::decode(buf),
            Err(PacketError::InvalidPacketHeader)
        ));
    }

    #[test]
    fn test_retry_returns_buffer_too_short_when_no_integrity_tag() {
        let mut buf = BytesMut::new();
        buf.put_u8(0b11110000); // Retry packet type
        buf.put_u32(1); // version
        buf.put_u8(0); // DCID length
        buf.put_u8(0); // SCID length
        // Only 10 bytes remaining, need at least 16 for integrity tag
        buf.put(&[0u8; 10][..]);

        assert!(matches!(
            LongHeaderPacket::decode(buf.freeze()),
            Err(PacketError::BufferTooShort)
        ));
    }

    #[test]
    fn test_decodes_valid_retry_packet_with_empty_token() {
        let mut buf = BytesMut::new();
        buf.put_u8(0b11110000); // Retry: long header + fixed bit + type 0x03
        buf.put_u32(1); // version
        buf.put_u8(4); // DCID length
        buf.put(&b"\x01\x02\x03\x04"[..]);
        buf.put_u8(4); // SCID length
        buf.put(&b"\x05\x06\x07\x08"[..]);
        // No retry token, just 16-byte integrity tag
        buf.put(&[0xAA; 16][..]);

        let packet = LongHeaderPacket::decode(buf.freeze()).unwrap();
        match packet {
            LongHeaderPacket::Retry {
                version,
                destination_connection_id,
                source_connection_id,
                retry_token,
                retry_integrity_tag,
            } => {
                assert_eq!(version, 1);
                assert_eq!(
                    destination_connection_id,
                    Bytes::from(&b"\x01\x02\x03\x04"[..])
                );
                assert_eq!(source_connection_id, Bytes::from(&b"\x05\x06\x07\x08"[..]));
                assert_eq!(retry_token.len(), 0);
                assert_eq!(retry_integrity_tag, Bytes::from(&[0xAA; 16][..]));
            }
            _ => panic!("Expected Retry variant"),
        }
    }

    #[test]
    fn test_decodes_valid_retry_packet_with_token() {
        let mut buf = BytesMut::new();
        buf.put_u8(0b11110000); // Retry
        buf.put_u32(1); // version
        buf.put_u8(0); // DCID length
        buf.put_u8(0); // SCID length
        buf.put(&b"my-retry-token"[..]); // 14-byte retry token
        buf.put(&[0xBB; 16][..]); // 16-byte integrity tag

        let packet = LongHeaderPacket::decode(buf.freeze()).unwrap();
        match packet {
            LongHeaderPacket::Retry {
                version,
                retry_token,
                retry_integrity_tag,
                ..
            } => {
                assert_eq!(version, 1);
                assert_eq!(retry_token, Bytes::from_static(b"my-retry-token"));
                assert_eq!(retry_integrity_tag, Bytes::from(&[0xBB; 16][..]));
            }
            _ => panic!("Expected Retry variant"),
        }
    }

    #[test]
    fn test_decodes_valid_initial_packet() {
        let mut buf = BytesMut::new();
        buf.put_u8(0xC1);
        buf.put_u32(1);
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(5);
        buf.put_u8(0x12);
        buf.put_u8(0x34);
        buf.put(&b"PIN"[..]);

        let packet = LongHeaderPacket::decode(buf.freeze()).unwrap();
        match packet {
            LongHeaderPacket::Initial {
                version,
                destination_connection_id,
                source_connection_id,
                token,
                packet_number,
                packet_payload,
            } => {
                assert_eq!(version, 1);
                assert_eq!(destination_connection_id.len(), 0);
                assert_eq!(source_connection_id.len(), 0);
                assert_eq!(token.len(), 0);
                assert_eq!(packet_number, Bytes::from_static(&[0x12, 0x34]));
                assert_eq!(packet_payload, Bytes::from_static(b"PIN"));
            }
            _ => panic!("Expected Initial variant"),
        }
    }

    #[test]
    fn test_returns_invalid_header_when_header_is_not_0rtt() {
        let buf = Bytes::from_static(&[0b01000000, 0, 0, 0, 1]);
        assert!(matches!(
            LongHeaderPacket::decode(buf),
            Err(PacketError::InvalidPacketHeader)
        ));
    }

    #[test]
    fn test_decodes_valid_zero_rtt_packet() {
        let mut buf = BytesMut::new();
        buf.put_u8(0b11010001);
        buf.put_u32(1);
        buf.put_u8(4);
        buf.put(&b"\x01\x02\x03\x04"[..]);
        buf.put_u8(4);
        buf.put(&b"\x05\x06\x07\x08"[..]);
        buf.put_u8(6);
        buf.put(&b"\x09\x0A"[..]);
        buf.put(&b"PING"[..]);

        let packet = LongHeaderPacket::decode(buf.freeze()).unwrap();
        match packet {
            LongHeaderPacket::ZeroRtt {
                version,
                destination_connection_id,
                source_connection_id,
                packet_number,
                packet_payload,
            } => {
                assert_eq!(version, 1);
                assert_eq!(
                    destination_connection_id,
                    Bytes::from(&b"\x01\x02\x03\x04"[..])
                );
                assert_eq!(source_connection_id, Bytes::from(&b"\x05\x06\x07\x08"[..]));
                assert_eq!(packet_number, Bytes::from(&b"\x09\x0A"[..]));
                assert_eq!(packet_payload, Bytes::from(&b"PING"[..]));
            }
            _ => panic!("Expected ZeroRtt variant"),
        }
    }

    #[test]
    fn test_returns_invalid_header_when_header_is_not_handshake() {
        let buf = Bytes::from_static(&[0b01000000, 0, 0, 0, 1]);
        assert!(matches!(
            LongHeaderPacket::decode(buf),
            Err(PacketError::InvalidPacketHeader)
        ));
    }

    #[test]
    fn test_decodes_valid_handshake_packet() {
        let mut buf = BytesMut::new();
        buf.put_u8(0b11100001);
        buf.put_u32(1);
        buf.put_u8(4);
        buf.put(&b"\x01\x02\x03\x04"[..]);
        buf.put_u8(4);
        buf.put(&b"\x05\x06\x07\x08"[..]);
        buf.put_u8(6);
        buf.put(&b"\x09\x0A"[..]);
        buf.put(&b"PING"[..]);

        let packet = LongHeaderPacket::decode(buf.freeze()).unwrap();
        match packet {
            LongHeaderPacket::Handshake {
                version,
                destination_connection_id,
                source_connection_id,
                packet_number,
                packet_payload,
            } => {
                assert_eq!(version, 1);
                assert_eq!(
                    destination_connection_id,
                    Bytes::from(&b"\x01\x02\x03\x04"[..])
                );
                assert_eq!(source_connection_id, Bytes::from(&b"\x05\x06\x07\x08"[..]));
                assert_eq!(packet_number, Bytes::from(&b"\x09\x0A"[..]));
                assert_eq!(packet_payload, Bytes::from(&b"PING"[..]));
            }
            _ => panic!("Expected Handshake variant"),
        }
    }
}
