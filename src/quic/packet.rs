pub(crate) type ByteVector = Vec<u8>;

enum PacketType {
    Initial = 0x00,
    // ZeroRtt = 0x01,
    // Handshake = 0x02,
    // Retry = 0x03,
}

struct LongHeader {
    // Header Form: The most significant bit (0x80) of the first byte
    // is set to 1 for long headers.
    header_form: u8,
    // The next bit (0x40) of byte 0 is set to 1, unless the packet is a Version Negotation packet.
    // Packets containing a 0 value for this bit are not valid packets in this version https://www.rfc-editor.org/rfc/rfc9000.html#name-packet-formats
    // and MUST be discarded. A value of 1 for this bit allows QUIC to coexist with other protocols; see https://www.rfc-editor.org/info/rfc7983
    fixed_bit: u8,
    // The next two bits (those with a mask of 0x30) of byte 0 contain a packet type.
    long_packet_type: PacketType,
    // The semantics of the lower four bits (those with a mask of 0x0f) of byte 0 are determined by the packet type.
    type_specific_bits: u8,
    // The QUIC Version is a 32-bit field that follows the first byte. This field indicates the version of QUIC that
    // is in use and determines how the rest of the protocol fields are interpreted.
    version: u32,
    // The byte following the version contains the lenght in bytes of the Destination Connection ID field that
    // follows it. This length is encoded as an 8-bit unsigned integer. In QUIC version 1, this value MUST NOT
    // exceed 20 bytes. Endpoints that receive a version 1 long header with a value larger than 20 MUST drop the
    // packet. In order to properly form a Version Negotiation packet, servers SHOULD be able to read longer connection IDs
    // from other QUIC versions. 
    destination_connection_id_length: u8,
    // The Destination Connection ID field follows the Destination Connection ID Length field, which indicates
    // the length of this field. This field is described in more detail [here](https://www.rfc-editor.org/rfc/rfc9000.html#negotiating-connection-ids)
    destination_connection_id: ByteVector,
    // The byte following the Destination Connection ID contains the lenght in bytes of the Source Connection ID field that
    // follows it. This length is encoded as an 8-bit unsigned integer. In QUIC version 1, this value MUST NOT exceed
    // 20 bytes. Endpoints that receive a version 1 long header with a value larger than 20 MUST drop the packet. In order
    // to properly form a Version Negotiation packet, servers SHOULD be able to read longer connection IDs from
    // other QUIC versions.
    source_connection_id_length: u8,
    // The Source Connection ID field follows the Source Connection ID Length field, which indicates the length of this field.
    // This field is described in more detail in Section 7.2 of RFC 9000 (link above).
    source_connection_id: ByteVector,
    // The remainder of the packet, if any, is type specific.
    type_specific_payload: ByteVector,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_long_header() {
        let long_header = LongHeader {
            header_form: 0x80,
            fixed_bit: 0x40,
            long_packet_type: PacketType::Initial,
            type_specific_bits: 0x0,
            version: 1,
            destination_connection_id_length: 8,
            destination_connection_id: vec![0; 8],
            source_connection_id_length: 8,
            source_connection_id: vec![0; 8],
            type_specific_payload: vec![],
        };

        assert_eq!(long_header.header_form & 0x80, 0x80);
        assert_eq!(long_header.fixed_bit & 0x40, 0x40);
        assert_eq!(long_header.long_packet_type as u8, 0x00);
        assert_eq!(long_header.type_specific_bits, 0x0);
        assert_eq!(long_header.version, 1);
        assert_eq!(long_header.destination_connection_id_length, 8);
        assert_eq!(long_header.source_connection_id_length, 8);
        assert_eq!(long_header.destination_connection_id.len(), 8);
        assert_eq!(long_header.source_connection_id.len(), 8);
        assert_eq!(long_header.type_specific_payload.len(), 0);
        }
    }