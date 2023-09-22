#![allow(dead_code)]
pub mod utils {
    use base64::{engine::general_purpose, Engine as _};
    use hex;

    pub fn b64_to_bytes(data: &str) -> Vec<u8> {
        general_purpose::STANDARD_NO_PAD
            .decode(data)
            .expect("invalid b64 string")
    }
    pub fn bytes_to_b64(data: &[u8]) -> String {
        general_purpose::STANDARD_NO_PAD.encode(data)
    }

    pub fn hex_to_bytes(data: &str) -> Vec<u8> {
        hex::decode(data).expect("invalid hex string")
    }
    pub fn bytes_to_hex(data: &[u8]) -> String {
        hex::encode(data)
    }

    pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
        let mut buf: Vec<u8> = vec![];

        for (x, y) in a.iter().zip(b.iter().cycle()) {
            buf.push(x ^ y);
        }

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::utils::*;

    #[test]
    fn test_hex_to_bytes() {
        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let b64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        let bytes = hex_to_bytes(hex);
        let res = bytes_to_b64(&bytes);

        assert_eq!(res, b64);
    }
}
