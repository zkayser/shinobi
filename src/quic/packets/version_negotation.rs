use crate::quic::packet::ByteVector;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_implementation() {
        let packet = VersionNegotiationPacket::default();
        assert_eq!(packet.version, 0);
        assert_eq!(packet.destination_connection_id.len(), 0);
        assert_eq!(packet.source_connection_id.len(), 0);
        assert_eq!(packet.supported_version, 1);
    }
}