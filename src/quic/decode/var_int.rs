#![allow(dead_code)]
use bytes::{Buf, Bytes};

pub enum VarInt {
    OneByte(u8),
    TwoBytes(u16),
    FourBytes(u32),
    EightBytes(u64),
}

const MASK: u8 = 0b00111111;

pub(crate) fn read(buf: &mut Bytes) -> Option<VarInt> {
    let first_byte = buf.get_u8();
    let prefix = first_byte >> 6;
    let length = 1 << prefix;
    match length {
        1 => Some(VarInt::OneByte(first_byte & MASK)),
        2 => {
            if buf.remaining() < 1 {
                return None;
            }
            let bytes: [u8; 2] = [first_byte & MASK, buf.get_u8()];
            Some(VarInt::TwoBytes(u16::from_be_bytes(bytes)))
        }
        4 => {
            if buf.remaining() < 3 {
                return None;
            }
            let bytes: [u8; 4] = [first_byte & MASK, buf.get_u8(), buf.get_u8(), buf.get_u8()];
            Some(VarInt::FourBytes(u32::from_be_bytes(bytes)))
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
            Some(VarInt::EightBytes(u64::from_be_bytes(bytes)))
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
        if let Some(VarInt::OneByte(value)) = read(&mut bytes.clone()) {
            assert_eq!(value, 37);
        } else {
            panic!("Expected OneByte variant");
        };
    }

    #[test]
    fn test_read_var_int_two_bytes_length() {
        let bytes = Bytes::from_static(&[0x7b, 0xbd]);
        if let Some(VarInt::TwoBytes(value)) = read(&mut bytes.clone()) {
            assert_eq!(value, 15293);
        } else {
            panic!("Expected TwoBytes variant");
        };
    }
}
