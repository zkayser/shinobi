#![allow(dead_code)]
use super::{Decode, PacketError};
use bytes::{Buf, Bytes};

#[derive(Debug)]
pub struct VersionNegotiationPacket {
    version: u32,
    destination_connection_id: Bytes,
    source_connection_id: Bytes,
    supported_version: Vec<u32>,
}

impl Default for VersionNegotiationPacket {
    fn default() -> Self {
        VersionNegotiationPacket {
            version: 0_u32,
            destination_connection_id: Bytes::new(),
            source_connection_id: Bytes::new(),
            supported_version: vec![1_u32],
        }
    }
}

impl Decode for VersionNegotiationPacket {
    fn decode(mut buf: Bytes) -> Result<VersionNegotiationPacket, PacketError> {
        if buf.len() < 7 {
            return Err(PacketError::BufferTooShort);
        }

        let header_byte = buf.get_u8();
        if header_byte & 0x80 == 0 {
            return Err(PacketError::InvalidPacketHeader);
        }

        let version = buf.get_u32();
        if version != 0 {
            return Err(PacketError::UnexpectedPacketType);
        }
        let destination_connection_id_length = buf.get_u8();
        let destination_connection_id =
            buf.copy_to_bytes(destination_connection_id_length as usize);
        let source_connection_id_length = buf.get_u8();
        let source_connection_id = buf.copy_to_bytes(source_connection_id_length as usize);
        let remainder = buf.remaining();
        let mut supported_versions = Vec::<u32>::new();
        for _ in 0..(remainder / 4) {
            let ver = buf.get_u32();
            supported_versions.push(ver);
        }

        Ok(VersionNegotiationPacket {
            version,
            destination_connection_id,
            source_connection_id,
            supported_version: supported_versions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};

    #[test]
    fn default_implementation() {
        let packet = VersionNegotiationPacket::default();
        assert_eq!(packet.version, 0);
        assert_eq!(packet.destination_connection_id.len(), 0);
        assert_eq!(packet.source_connection_id.len(), 0);
        assert_eq!(packet.supported_version, vec![1_u32]);
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
            Err(PacketError::InvalidPacketHeader)
        ));
    }

    #[test]
    fn test_decode_not_version_negotiation() {
        let buf = Bytes::from_static(&[0x80u8, 0, 0, 0, 1, 0, 0, 0, 0]);
        assert!(matches!(
            VersionNegotiationPacket::decode(buf),
            Err(PacketError::UnexpectedPacketType)
        ));
    }

    #[test]
    fn test_decodes_valid_vn_packet() {
        let mut buf = BytesMut::with_capacity(1024);
        buf.put_u8(0x80_u8);
        buf.put_u32(0_u32);
        buf.put_u8(8_u8);
        buf.put(&b"\x01\x02\x03\x04\x05\x06\x07\x08"[..]);
        buf.put_u8(8_u8);
        buf.put(&b"\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"[..]);
        buf.put_u32(1_u32);
        buf.put_u32(2_u32);

        let packet = VersionNegotiationPacket::decode(buf.freeze()).unwrap();
        assert_eq!(packet.version, 0);
        assert_eq!(packet.destination_connection_id.len(), 8);
        assert_eq!(packet.source_connection_id.len(), 8);
        assert_eq!(packet.supported_version, vec![1_u32, 2_u32]);
    }
}
