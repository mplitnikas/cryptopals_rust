#![allow(dead_code)]
pub mod utils {
    use base64::{engine::general_purpose, Engine as _};
    use hex;

    // pub fn hex_string_to_b64_string(data: &str) -> String {
    //     let bytes = hex_to_bytes(data);
    //     bytes_to_b64(&bytes)
    // }

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

        for (x, y) in a.iter().zip(b.iter()) {
            buf.push(x ^ y);
        }

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::utils::*;

    #[test]
    fn challenge_1() {
        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let b64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        let bytes = hex_to_bytes(hex);
        let res = bytes_to_b64(&bytes);

        assert_eq!(res, b64);
    }

    #[test]
    fn challenge_2() {
        let hex1 = "1c0111001f010100061a024b53535009181c";
        let hex2 = "686974207468652062756c6c277320657965";
        let expected = "746865206b696420646f6e277420706c6179";

        let xord = bytes_to_hex(&xor_bytes(&hex_to_bytes(hex1), &hex_to_bytes(hex2)));
        assert_eq!(xord, expected);
    }
}
