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

    pub fn score_letter_frequency(data: &str) -> u8 {
        // returns range of 0-26
        let common_letters = "etaoinshrdlucmwfgypbvkjxqz".as_bytes();
        let mut score = 0;
        let filtered_text: Vec<char> = data
            .to_lowercase()
            .chars()
            .filter(|&c| c.is_alphabetic())
            .collect();
        let filtered_len = filtered_text.len();

        for char in filtered_text {
            let freq = common_letters.iter().position(|&c| c == char as u8);
            if let Some(value) = freq {
                score += 26 - value;
            }
        }
        // average score so we're not biased on string length
        score = score / (filtered_len + 1);
        // deduct points for non-letter chars
        score.saturating_sub(data.len() - filtered_len) as u8
    }

    pub fn find_single_byte_xor_decode(data: &[u8]) -> (String, u8) {
        let mut score = 0;
        let mut out_string = vec![];
        let mut char = 0;
        for byte in 0..=255 {
            let output = xor_bytes(data, &[byte]);
            let current_score = score_letter_frequency(&String::from_utf8_lossy(&output));
            if current_score > score {
                score = current_score;
                out_string = output;
                char = byte;
            }
        }
        (String::from_utf8_lossy(&out_string).to_string(), char)
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

    #[test]
    fn test_letter_freq() {
        let english_score = score_letter_frequency(
            "It was the best of times, it was the worst of times! Incredible really.",
        );
        let gibberish_score = score_letter_frequency(
            "dkbfsxdk.bnrslbnpoeasgpsreblnkxcb,mxkcvb289tp924lkewbkmbnblkeai329k42jporbprsdbnrsdlktnribtu",
        );

        assert!(english_score > gibberish_score);
    }

    #[test]
    fn challenge_3() {
        let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let bytes = hex_to_bytes(input);
        let (output, chr) = find_single_byte_xor_decode(&bytes);

        assert_eq!(output, "Cooking MC's like a pound of bacon");
        assert_eq!(chr, 88);
    }
}
