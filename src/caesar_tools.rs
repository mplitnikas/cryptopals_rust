pub mod caesar {
    use crate::common::utils;

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

    pub fn find_single_byte_xor_decode(data: &[u8]) -> (String, u8, u8) {
        let mut score = 0;
        let mut out_string = vec![];
        let mut char = 0;
        for byte in 0..=255 {
            let output = utils::xor_bytes(data, &[byte]);
            let current_score = score_letter_frequency(&String::from_utf8_lossy(&output));
            if current_score > score {
                score = current_score;
                out_string = output;
                char = byte;
            }
        }
        (
            String::from_utf8_lossy(&out_string).to_string(),
            char,
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
