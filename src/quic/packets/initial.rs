#![allow(dead_code)]
use bytes::{Buf, Bytes};
use thiserror::Error;

#[derive(Error, Debug)]
enum PacketError {
    #[error("Not an initial packet")]
    NotInitialPacket,
    #[error("Invalid packet header")]
    InvalidPacketHeader,
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
        let header_byte = buf.get_u8();
        if header_byte & 0b11000000 != 0b11000000 {
            return Err(PacketError::InvalidPacketHeader);
        }

        if header_byte & 0b00110000 != 0b00110000 {
            return Err(PacketError::NotInitialPacket);
        }

        Ok(InitialPacket {
            version: 1,
            destination_connection_id: Bytes::new(),
            source_connection_id: Bytes::new(),
            token: Bytes::new(),
            packet_number: Bytes::new(),
            packet_payload: Bytes::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
