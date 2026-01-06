#![allow(dead_code)]
use bytes::{Buf, Bytes};

const MASK: u8 = 0b00111111;

pub(crate) fn read(buf: &mut Bytes) -> Option<u64> {
    let first_byte = buf.get_u8();
    let prefix = first_byte >> 6;
    let length = 1 << prefix;
    match length {
        1 => Some((first_byte & MASK) as u64),
        2 => {
            if buf.remaining() < 1 {
                return None;
            }
            let bytes: [u8; 2] = [first_byte & MASK, buf.get_u8()];
            Some(u16::from_be_bytes(bytes) as u64)
        }
        4 => {
            if buf.remaining() < 3 {
                return None;
            }
            let bytes: [u8; 4] = [first_byte & MASK, buf.get_u8(), buf.get_u8(), buf.get_u8()];
            Some(u32::from_be_bytes(bytes) as u64)
        }
        8 => {
            if buf.remaining() < 7 {
                return None;
            }
            let bytes: [u8; 8] = [
                first_byte & MASK,
                buf.get_u8(),
                buf.get_u8(),
                buf.get_u8(),
                buf.get_u8(),
                buf.get_u8(),
                buf.get_u8(),
                buf.get_u8(),
            ];
            Some(u64::from_be_bytes(bytes))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    // Test examples are based on some examples in Sample Variable-length Integer Decoding section of RFC 9000,
    // Appendix A.1 https://www.rfc-editor.org/rfc/rfc9000.html#section-a.1

    #[test]
    fn test_read_var_int_one_byte_length() {
        let bytes = Bytes::from_static(&[0x25]);
        if let Some(value) = read(&mut bytes.clone()) {
            assert_eq!(value, 37);
        } else {
            panic!("Expected OneByte variant");
        };
    }

    #[test]
    fn test_read_var_int_two_bytes_length() {
        let bytes = Bytes::from_static(&[0x7b, 0xbd]);
        if let Some(value) = read(&mut bytes.clone()) {
            assert_eq!(value, 15293);
        } else {
            panic!("Expected TwoBytes variant");
        };
    }

    #[test]
    fn test_read_var_int_four_bytes_length() {
        // the four-byte sequence 0x9d7f3e7d decodes to 494,878,333
        let bytes = Bytes::from_static(&[0x9d, 0x7f, 0x3e, 0x7d]);
        if let Some(value) = read(&mut bytes.clone()) {
            assert_eq!(value, 494_878_333);
        } else {
            panic!("Expected FourBytes variant");
        };
    }

    #[test]
    fn test_read_var_int_eight_bytes_length() {
        // the eight-byte sequence 0xc2197c5eff14e88c decodes to the decimal value 151,288,809,941,952,652
        let bytes = Bytes::from_static(&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]);
        if let Some(value) = read(&mut bytes.clone()) {
            assert_eq!(value, 151_288_809_941_952_652);
        } else {
            panic!("Expected EightBytes variant");
        };
    }

    #[test]
    fn test_returns_none_when_provided_prefix_01_but_insufficient_bytes() {
        let bytes = Bytes::from_static(&[0b01111111]); // Prefix 01 indicates 2-byte length
        assert!(read(&mut bytes.clone()).is_none());
    }

    #[test]
    fn test_returns_none_when_provided_insufficient_bytes_given_four_byte_prefix() {
        let bytes = Bytes::from_static(&[0b10111111, 0b11111111]); // Prefix 10 indicates 4-byte length
        assert!(read(&mut bytes.clone()).is_none());
    }

    #[test]
    fn test_returns_none_when_provided_insufficient_bytes_given_eight_byte_prefix() {
        let bytes =
            Bytes::from_static(&[0b11111111, 0b11111111, 0b11111111, 0b11111111, 0b11111111]); // Prefix 11 indicates 8-byte length
        assert!(read(&mut bytes.clone()).is_none());
    }
}
