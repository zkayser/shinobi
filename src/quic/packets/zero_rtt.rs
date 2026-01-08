#![allow(dead_code)]
use crate::quic::decode::var_int;
use bytes::{Buf, Bytes};
use thiserror::Error;

#[derive(Error, Debug)]
enum PacketError {
    #[error("Not a 0-RTT packet")]
    Not0RttPacket,
    #[error("Invalid packet header")]
    InvalidPacketHeader,
    #[error("Buffer too short")]
    BufferTooShort,
}

#[derive(Debug)]
pub struct ZeroRttPacket {
    version: u32,
    destination_connection_id: Bytes,
    source_connection_id: Bytes,
    packet_number: Bytes,
    packet_payload: Bytes,
}

const HEADER_MASK: u8 = 0b11010000;
const PACKET_NUMBER_LENGTH_MASK: u8 = 0b00000011;

impl ZeroRttPacket {
    fn decode(mut buf: Bytes) -> Result<ZeroRttPacket, PacketError> {
        if buf.is_empty() {
            return Err(PacketError::BufferTooShort);
        }

        let header_byte = buf.get_u8();
        if header_byte & HEADER_MASK != HEADER_MASK {
            return Err(PacketError::InvalidPacketHeader);
        }

        let packet_number_length = (header_byte & PACKET_NUMBER_LENGTH_MASK) + 1;
        let version = buf.get_u32();

        let destination_connection_id_length = buf.get_u8() as usize;
        let destination_connection_id = buf.copy_to_bytes(destination_connection_id_length);

        let source_connection_id_length = buf.get_u8() as usize;
        let source_connection_id = buf.copy_to_bytes(source_connection_id_length);

        let Some(length) = var_int::read(&mut buf) else {
            return Err(PacketError::BufferTooShort);
        };

        let mut content = buf.copy_to_bytes(length as usize);

        let packet_number = content.copy_to_bytes(packet_number_length as usize);
        let packet_payload = content;

        Ok(ZeroRttPacket {
            version,
            destination_connection_id,
            source_connection_id,
            packet_number,
            packet_payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // use bytes::BufMut;
    // use bytes::BytesMut;

    #[test]
    fn test_returns_invalid_packet_header_when_header_is_not_0rtt() {
        let buf = Bytes::from_static(&[0b01000000, 0, 0, 0, 1]);
        assert!(matches!(
            ZeroRttPacket::decode(buf),
            Err(PacketError::InvalidPacketHeader)
        ));
    }

    #[test]
    fn test_returns_buffer_too_short_when_buffer_is_empty() {
        let buf = Bytes::from_static(&[]);
        assert!(matches!(
            ZeroRttPacket::decode(buf),
            Err(PacketError::BufferTooShort)
        ));
    }
}
