#![allow(dead_code)]
use crate::quic::decode::var_int;
use bytes::{Buf, Bytes};
use thiserror::Error;

#[derive(Error, Debug)]
enum PacketError {
    #[error("Not an initial packet")]
    NotInitialPacket,
    #[error("Invalid packet header")]
    InvalidPacketHeader,
    #[error("Buffer too short")]
    BufferTooShort,
    #[error("Invalid variable length integer encoding")]
    InvalidVarInt,
}

#[derive(Debug)]
pub struct InitialPacket {
    version: u32,
    destination_connection_id: Bytes,
    source_connection_id: Bytes,
    token: Bytes,
    packet_number: Bytes,
    packet_payload: Bytes,
}

impl InitialPacket {
    fn decode(mut buf: Bytes) -> Result<InitialPacket, PacketError> {
        if buf.is_empty() {
            return Err(PacketError::BufferTooShort);
        }

        let header_byte = buf.get_u8();
        if header_byte & 0b11000000 != 0b11000000 {
            return Err(PacketError::InvalidPacketHeader);
        }

        if header_byte & 0b00110000 != 0 {
            return Err(PacketError::NotInitialPacket);
        }

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

        let Some(token_length) = var_int::read(&mut buf) else {
            return Err(PacketError::InvalidVarInt);
        };

        if buf.remaining() < token_length as usize {
            return Err(PacketError::BufferTooShort);
        }
        let token = buf.copy_to_bytes(token_length as usize);

        let Some(length) = var_int::read(&mut buf) else {
            return Err(PacketError::InvalidVarInt);
        };
        if buf.remaining() < length as usize {
            return Err(PacketError::BufferTooShort);
        }

        let packet_number_length = header_byte & 0b00000011;
        if length < (packet_number_length as u64) {
            return Err(PacketError::InvalidPacketHeader);
        }

        let mut content = buf.copy_to_bytes(length as usize);

        let packet_number = content.copy_to_bytes(packet_number_length as usize);
        let packet_payload = content;

        Ok(InitialPacket {
            version,
            destination_connection_id,
            source_connection_id,
            token,
            packet_number,
            packet_payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BufMut;
    use bytes::BytesMut;

    #[test]
    fn test_returns_invalid_packet_header_error_when_header_not_valid() {
        let buf = Bytes::from_static(&[0b01000000, 0, 0, 0, 1]);
        assert!(matches!(
            InitialPacket::decode(buf),
            Err(PacketError::InvalidPacketHeader)
        ));
    }

    #[test]
    fn test_returns_not_initial_packet_error_when_not_initial() {
        let buf = Bytes::from_static(&[0b11010000, 0, 0, 0, 1]);
        assert!(matches!(
            InitialPacket::decode(buf),
            Err(PacketError::NotInitialPacket)
        ));
    }

    #[test]
    fn test_decodes_valid_initial_packet() {
        let mut buf = BytesMut::new();
        buf.put_u8(0xC1); // Header byte: 11000001 -- header and reserved bits set, plus packet number length set to 1 byte
        buf.put_u32(1);
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(5);
        buf.put_u8(0x12);
        buf.put(&b"PING"[..]);

        let packet = InitialPacket::decode(buf.freeze()).unwrap();

        assert_eq!(packet.version, 1);
        assert_eq!(packet.destination_connection_id.len(), 0);
        assert_eq!(packet.source_connection_id.len(), 0);
        assert_eq!(packet.token.len(), 0);
        assert_eq!(packet.packet_number.len(), 1);
        assert_eq!(packet.packet_number[0], 0x12);
        assert_eq!(packet.packet_payload, Bytes::from_static(b"PING"));
    }
}
