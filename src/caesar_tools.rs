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
mod tests {
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
