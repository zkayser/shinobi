use crate::quic::packet::ByteVector;
use bytes::{Buf, Bytes};
use thiserror::Error;

pub struct VersionNegotiationPacket {
    version: u32,
    destination_connection_id: ByteVector,
    source_connection_id: ByteVector,
    supported_version: u32,
}

impl Default for VersionNegotiationPacket {
    fn default() -> Self {
        VersionNegotiationPacket {
            version: 0 as u32,
            destination_connection_id: vec![],
            source_connection_id: vec![],
            supported_version: 1 as u32,
        }
    }
}

#[derive(Error, Debug)]
enum PacketError {
    #[error("Packet is too short")]
    BufferTooShort,
    #[error("Not a long header packet")]
    NotLongHeader,
    #[error("Not a version negotiation packet (version != 0)")]
    NotVersionNegotiation,
}

impl VersionNegotiationPacket {
    fn decode(mut buf: Bytes) -> Result<VersionNegotiationPacket, PacketError> {
        if buf.len() < 7 {
            return Err(PacketError::BufferTooShort)
        }

        let header_byte = buf.get_u8();
        if header_byte & 0x80 == 0 {
            return Err(PacketError::NotLongHeader)
        }
        
        // Decoding logic to be implemented
        return Ok(VersionNegotiationPacket::default());
    }
}

#[cfg(test)]
mod tests {
    use bytes::buf;

    use super::*;

    #[test]
    fn default_implementation() {
        let packet = VersionNegotiationPacket::default();
        assert_eq!(packet.version, 0);
        assert_eq!(packet.destination_connection_id.len(), 0);
        assert_eq!(packet.source_connection_id.len(), 0);
        assert_eq!(packet.supported_version, 1);
    }

    #[test]
    fn test_decode_too_short() {
        let buf = Bytes::from_static(&[0u8; 5]);
        assert!(matches!(
            VersionNegotiationPacket::decode(buf),
            Err(PacketError::BufferTooShort)
        ));
    }

    #[test]
    fn test_decode_not_long_header() {
        let buf = Bytes::from_static(&[0x7Fu8; 10]);
        assert!(matches!(
            VersionNegotiationPacket::decode(buf),
            Err(PacketError::NotLongHeader)
        ));
    }
}