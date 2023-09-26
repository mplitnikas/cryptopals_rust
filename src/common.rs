#![allow(dead_code)]
pub mod utils {
    use base64::{engine::general_purpose, Engine as _};
    use hex;

    pub fn b64_to_bytes(data: &str) -> Vec<u8> {
        general_purpose::STANDARD
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

    pub fn hamming_dist(a: &[u8], b: &[u8]) -> usize {
        a.iter()
            .zip(b.iter())
            .map(|(x, y)| (x ^ y).count_ones())
            .sum::<u32>() as usize
    }
}

pub mod caesar {
    use crate::common::utils;
    use std::collections::HashMap;

    pub fn score_letter_frequency(data: &str) -> f32 {
        let letter_scores: HashMap<char, f32> = HashMap::from([
            (' ', 100.0),
            ('.', 5.0),
            (',', 5.0),
            ('\'', 1.5),
            ('e', 56.88),
            ('a', 43.31),
            ('r', 38.64),
            ('i', 38.45),
            ('o', 36.51),
            ('t', 35.43),
            ('n', 33.92),
            ('s', 29.23),
            ('l', 27.98),
            ('c', 23.13),
            ('u', 18.51),
            ('d', 17.25),
            ('p', 16.14),
            ('m', 15.36),
            ('h', 15.31),
            ('g', 12.59),
            ('b', 10.56),
            ('f', 9.24),
            ('y', 9.06),
            ('w', 6.57),
            ('k', 5.61),
            ('v', 5.13),
            ('x', 1.48),
            ('z', 1.39),
            ('j', 1.00),
            ('q', 1.00),
        ]);

        let mut score: f32 = 0.0;
        let filtered_text: Vec<char> = data.to_lowercase().chars().collect();

        for char in filtered_text {
            let freq = letter_scores
                .iter()
                .find(|&(&letter, _value)| letter == char);
            if let Some(value) = freq {
                score += *value.1;
            }
        }

        // normalize to string length
        // (not strictly necessary across a single cyphertext)
        score / data.len() as f32
    }

    pub fn find_single_byte_xor_decode(data: &[u8]) -> (String, u8, f32) {
        let mut score: f32 = 0.0;
        let mut out_string = vec![];
        let mut best_byte: u8 = 0;
        for byte in 0..=255 {
            let output = utils::xor_bytes(data, &[byte]);
            let candidate_decoded = String::from_utf8_lossy(&output);
            let current_score = score_letter_frequency(&candidate_decoded);
            if current_score > score {
                score = current_score;
                out_string = output;
                best_byte = byte;
            }
        }
        (
            String::from_utf8_lossy(&out_string).to_string(),
            best_byte,
            score,
        )
    }
}

#[cfg(test)]
mod utils_tests {
    use super::utils::*;

    #[test]
    fn test_hex_to_bytes() {
        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let b64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        let bytes = hex_to_bytes(hex);
        let res = bytes_to_b64(&bytes);

        assert_eq!(res, b64);
    }

    #[test]
    fn test_hamming_dist() {
        let string1 = "this is a test";
        let string2 = "wokka wokka!!!";

        assert_eq!(hamming_dist(string1.as_bytes(), string2.as_bytes()), 37);
    }
}

#[cfg(test)]
mod caesar_tests {
    use super::caesar::*;

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
}
