use crate::quic::decode::var_int;
use bytes::{Buf, Bytes};
use thiserror::Error;

#[derive(Error, Debug)]
enum PacketError {
    #[error("Not a Handshake Packet")]
    NotHandshakePacket,
    #[error("Invalid packet header")]
    InvalidPacketHeader,
    #[error("Buffer too short")]
    BufferTooShort,
}

#[derive(Debug)]
pub struct HandshakePacket {
    version: u32,
    destination_connection_id: Bytes,
    source_connection_id: Bytes,
    packet_number: Bytes,
    packet_payload: Bytes,
}

const HEADER_MASK: u8 = 0b11100000;
const PACKET_NUMBER_LENGTH_MASK: u8 = 0b00000011;

impl HandshakePacket {
    fn decode(mut buf: Bytes) -> Result<HandshakePacket, PacketError> {
        if buf.is_empty() {
            return Err(PacketError::BufferTooShort);
        }

        let header = buf.get_u8();
        if header & HEADER_MASK != HEADER_MASK {
            return Err(PacketError::InvalidPacketHeader);
        }

        let packet_number_length = (header & PACKET_NUMBER_LENGTH_MASK) + 1;
        let version = buf.get_u32();

        let destination_connection_id_length = buf.get_u8();
        let destination_connection_id =
            buf.copy_to_bytes(destination_connection_id_length as usize);

        let source_connection_id_length = buf.get_u8();
        let source_connection_id = buf.copy_to_bytes(source_connection_id_length as usize);

        let Some(length) = var_int::read(&mut buf) else {
            return Err(PacketError::BufferTooShort);
        };

        let mut content = buf.copy_to_bytes(length as usize);

        let packet_number = content.copy_to_bytes(packet_number_length as usize);
        let packet_payload = content;

        Ok(HandshakePacket {
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
    use bytes::BufMut;
    use bytes::BytesMut;

    #[test]
    fn test_returns_invalid_packet_header_when_header_is_not_handshake() {
        let buf = Bytes::from_static(&[0b01000000, 0, 0, 1]);
        assert!(matches!(
            HandshakePacket::decode(buf),
            Err(PacketError::InvalidPacketHeader)
        ));
    }

    #[test]
    fn test_returns_buffer_too_short_when_not_sufficient_length() {
        let buf = Bytes::from_static(&[]);
        assert!(matches!(
            HandshakePacket::decode(buf),
            Err(PacketError::BufferTooShort)
        ));
    }
}
