#![allow(dead_code)]
use super::PacketError;
use bytes::{Buf, Bytes};

/// A 1-RTT Short Header packet per RFC 9000 Section 17.3.
#[derive(Debug)]
pub struct ShortHeaderPacket {
    pub first_byte: u8,
    pub destination_connection_id: Bytes,
    pub packet_number: Bytes,
    pub packet_payload: Bytes,
}

const HEADER_FORM_BIT: u8 = 0x80;
const FIXED_BIT: u8 = 0x40;
const PACKET_NUMBER_LENGTH_MASK: u8 = 0x03;

impl ShortHeaderPacket {
    /// Decode a 1-RTT Short Header packet.
    ///
    /// `dcid_len` is the expected Destination Connection ID length, which must
    /// be known from prior handshake negotiation (RFC 9000 Section 17.3).
    pub fn decode(mut buf: Bytes, dcid_len: usize) -> Result<Self, PacketError> {
        if buf.is_empty() {
            return Err(PacketError::BufferTooShort);
        }

        let first_byte = buf.get_u8();

        // Header Form bit must be 0 for short headers
        if first_byte & HEADER_FORM_BIT != 0 {
            return Err(PacketError::InvalidPacketHeader);
        }
        // Fixed bit must be 1
        if first_byte & FIXED_BIT == 0 {
            return Err(PacketError::InvalidPacketHeader);
        }

        let packet_number_length = (first_byte & PACKET_NUMBER_LENGTH_MASK) + 1;

        if buf.remaining() < dcid_len {
            return Err(PacketError::BufferTooShort);
        }
        let destination_connection_id = buf.copy_to_bytes(dcid_len);

        if buf.remaining() < packet_number_length as usize {
            return Err(PacketError::BufferTooShort);
        }
        let packet_number = buf.copy_to_bytes(packet_number_length as usize);

        if buf.is_empty() {
            return Err(PacketError::BufferTooShort);
        }
        let packet_payload = buf.copy_to_bytes(buf.remaining());

        Ok(ShortHeaderPacket {
            first_byte,
            destination_connection_id,
            packet_number,
            packet_payload,
        })
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
            ShortHeaderPacket::decode(buf, 0),
            Err(PacketError::BufferTooShort)
        ));
    }

    #[test]
    fn test_returns_invalid_header_when_header_form_is_long() {
        let buf = Bytes::from_static(&[0b11000000, 0, 0, 0]);
        assert!(matches!(
            ShortHeaderPacket::decode(buf, 0),
            Err(PacketError::InvalidPacketHeader)
        ));
    }

    #[test]
    fn test_returns_invalid_header_when_fixed_bit_not_set() {
        let buf = Bytes::from_static(&[0b00000000, 0, 0, 0]);
        assert!(matches!(
            ShortHeaderPacket::decode(buf, 0),
            Err(PacketError::InvalidPacketHeader)
        ));
    }

    #[test]
    fn test_returns_buffer_too_short_when_dcid_missing() {
        let buf = Bytes::from_static(&[0b01000000]);
        assert!(matches!(
            ShortHeaderPacket::decode(buf, 8),
            Err(PacketError::BufferTooShort)
        ));
    }

    #[test]
    fn test_returns_buffer_too_short_when_packet_number_missing() {
        let mut buf = BytesMut::new();
        buf.put_u8(0b01000001); // pn_len = 2
        buf.put(&[0u8; 4][..]); // 4-byte DCID
        // No bytes left for packet number

        assert!(matches!(
            ShortHeaderPacket::decode(buf.freeze(), 4),
            Err(PacketError::BufferTooShort)
        ));
    }

    #[test]
    fn test_returns_buffer_too_short_when_payload_empty() {
        let mut buf = BytesMut::new();
        buf.put_u8(0b01000000); // pn_len = 1
        buf.put(&[0u8; 4][..]); // 4-byte DCID
        buf.put_u8(0x01); // 1-byte packet number
        // No payload bytes

        assert!(matches!(
            ShortHeaderPacket::decode(buf.freeze(), 4),
            Err(PacketError::BufferTooShort)
        ));
    }

    #[test]
    fn test_decodes_valid_short_header_packet() {
        let mut buf = BytesMut::new();
        // 0b01000001: header form=0, fixed=1, spin=0, reserved=00, key_phase=0, pn_len=2
        buf.put_u8(0b01000001);
        buf.put(&b"\x01\x02\x03\x04"[..]); // 4-byte DCID
        buf.put(&b"\x09\x0A"[..]); // 2-byte packet number
        buf.put(&b"PING"[..]); // payload

        let packet = ShortHeaderPacket::decode(buf.freeze(), 4).unwrap();
        assert_eq!(packet.first_byte, 0b01000001);
        assert_eq!(
            packet.destination_connection_id,
            Bytes::from(&b"\x01\x02\x03\x04"[..])
        );
        assert_eq!(packet.packet_number, Bytes::from(&b"\x09\x0A"[..]));
        assert_eq!(packet.packet_payload, Bytes::from(&b"PING"[..]));
    }

    #[test]
    fn test_preserves_header_bits() {
        let mut buf = BytesMut::new();
        // 0b01111100: spin=1, reserved=11, key_phase=1, pn_len=1
        buf.put_u8(0b01111100);
        buf.put(&b"\xAA\xBB"[..]); // 2-byte DCID
        buf.put_u8(0x42); // 1-byte packet number
        buf.put(&b"DATA"[..]); // payload

        let packet = ShortHeaderPacket::decode(buf.freeze(), 2).unwrap();
        assert_eq!(packet.first_byte, 0b01111100);
        assert_eq!(packet.first_byte & 0x20, 0x20); // spin bit set
        assert_eq!(packet.first_byte & 0x18, 0x18); // reserved bits set
        assert_eq!(packet.first_byte & 0x04, 0x04); // key phase set
    }

    #[test]
    fn test_decodes_with_zero_length_dcid() {
        let mut buf = BytesMut::new();
        buf.put_u8(0b01000000); // pn_len = 1
        buf.put_u8(0x01); // 1-byte packet number
        buf.put(&b"HELLO"[..]); // payload

        let packet = ShortHeaderPacket::decode(buf.freeze(), 0).unwrap();
        assert_eq!(packet.destination_connection_id.len(), 0);
        assert_eq!(packet.packet_number, Bytes::from_static(&[0x01]));
        assert_eq!(packet.packet_payload, Bytes::from(&b"HELLO"[..]));
    }

    #[test]
    fn test_decodes_with_four_byte_packet_number() {
        let mut buf = BytesMut::new();
        // 0b01000011: pn_len = 4
        buf.put_u8(0b01000011);
        buf.put(&b"\x01\x02\x03\x04"[..]); // 4-byte DCID
        buf.put(&b"\x00\x01\x00\x01"[..]); // 4-byte packet number
        buf.put(&b"X"[..]); // minimal payload

        let packet = ShortHeaderPacket::decode(buf.freeze(), 4).unwrap();
        assert_eq!(packet.packet_number, Bytes::from(&b"\x00\x01\x00\x01"[..]));
        assert_eq!(packet.packet_payload, Bytes::from(&b"X"[..]));
    }
}
