pub mod utils {
    use base64::{engine::general_purpose, Engine as _};
    use hex;
    use rand::Rng;
    use std::fs;
    use std::path::Path;

    pub fn b64_to_bytes(data: &str) -> Vec<u8> {
        general_purpose::STANDARD
            .decode(data)
            .expect("invalid b64 string")
    }
    pub fn bytes_to_b64(data: &[u8]) -> String {
        general_purpose::STANDARD_NO_PAD.encode(data)
    }
    pub fn bytes_from_b64_file<P: AsRef<Path>>(path: P) -> Vec<u8> {
        let file = fs::read(path).expect("couldn't open file");
        let file: Vec<u8> = file.iter().filter(|&c| *c != '\n' as u8).cloned().collect();
        b64_to_bytes(&String::from_utf8(file).unwrap())
    }
    pub fn lines_from_b64_file<P: AsRef<Path>>(path: P) -> Vec<Vec<u8>> {
        let file = String::from_utf8(fs::read(path).expect("couldn't open file")).unwrap();
        file.split(|c| c == '\n')
            .map(|line| b64_to_bytes(line))
            .filter(|l| !l.is_empty())
            .collect()
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

    pub fn generate_random_string(length: usize) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                             abcdefghijklmnopqrstuvwxyz\
                             0123456789";
        let mut rng = rand::thread_rng();
        let random_string: String = (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect();
        random_string
    }
}

pub mod caesar {
    use super::utils;
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

    pub fn find_best_keysizes(data: &[u8]) -> Vec<usize> {
        let mut best_keysizes: Vec<(usize, f32)> = vec![];

        for keysize in 2..=40 {
            let chunks: Vec<Vec<u8>> = data.chunks(keysize).take(4).map(|c| c.to_vec()).collect();

            let mut sum = 0;
            let mut count = 0;
            for i in 0..chunks.len() {
                for j in i + 1..chunks.len() {
                    let result = utils::hamming_dist(&chunks[i], &chunks[j]);
                    sum += result;
                    count += 1;
                }
            }
            // average of hamming distances
            let dist = sum as f32 / count as f32;
            // normalize to keysize
            let dist = dist / keysize as f32;

            best_keysizes.push((keysize, dist));
            best_keysizes.sort_by(|a, b| a.1.partial_cmp(&b.1).expect("can't compare!?"))
        }
        best_keysizes[..5].to_vec().iter().map(|x| x.0).collect()
    }

    pub fn transpose_by_keysize(data: &[u8], keysize: usize) -> Vec<Vec<u8>> {
        let mut output_vec: Vec<Vec<u8>> = vec![Vec::new(); keysize];
        data.iter()
            .zip((0..keysize).cycle())
            .for_each(|(&byte, index)| {
                output_vec[index].push(byte);
            });

        output_vec
    }
}

pub mod aes {
    use super::utils;
    use aes::{
        self,
        cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit},
    };
    use ecb;

    type Aes128EcbEnc = ecb::Encryptor<aes::Aes128>;
    type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;

    pub fn ecb_encrypt_single(data: &[u8], key: &[u8]) -> Vec<u8> {
        let data = pkcs7_pad(data, 16);

        let mut buf = [0u8; 16];
        buf.copy_from_slice(&data);
        Aes128EcbEnc::new(key.into()).encrypt_block_mut((&mut buf).into());

        buf.to_vec()
    }
    pub fn ecb_decrypt_single(data: &[u8], key: &[u8]) -> Vec<u8> {
        if data.len() != 16 {
            panic!("invalid data length");
        };

        let mut buf = [0u8; 16];
        buf.copy_from_slice(data);
        Aes128EcbDec::new(key.into()).decrypt_block_mut((&mut buf).into());

        let res = buf.to_vec();
        pkcs7_unpad(&res)
    }
    pub fn ecb_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
        let mut res = vec![];
        for chunk in data.chunks(16) {
            res.extend(ecb_encrypt_single(chunk, key));
        }
        res
    }
    pub fn ecb_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
        let mut res = vec![];
        for chunk in data.chunks(16) {
            res.extend(ecb_decrypt_single(chunk, key));
        }
        res
    }

    pub fn pkcs7_pad(data: &[u8], blocksize: usize) -> Vec<u8> {
        let diff = match data.len().partial_cmp(&blocksize) {
            Some(std::cmp::Ordering::Less) => blocksize - data.len(),
            Some(std::cmp::Ordering::Equal) => 0,
            Some(std::cmp::Ordering::Greater) => blocksize - (data.len() % blocksize),
            None => panic!("comparison failed"),
        };
        let pad = vec![diff as u8; diff];

        let mut output = vec![];
        output.extend_from_slice(data);
        output.extend_from_slice(&pad);
        output
    }

    pub fn pkcs7_unpad(data: &[u8]) -> Vec<u8> {
        let last_byte = data[data.len() - 1] as usize;
        if last_byte >= data.len() {
            // can't be padding if it's longer than data
            return data.to_vec();
        }
        let maybe_padding = &data[data.len() - last_byte..];
        if maybe_padding.len() == last_byte && maybe_padding.iter().all(|&x| x == last_byte as u8) {
            data[0..data.len() - last_byte].to_vec()
        } else {
            data.to_vec() // none, or maybe invalid padding
        }
    }

    pub fn cbc_single_encrypt(block: &[u8], key: &[u8], prev_block: &[u8]) -> Vec<u8> {
        let xored = utils::xor_bytes(block, prev_block);
        ecb_encrypt_single(&xored, key)
    }

    pub fn cbc_single_decrypt(block: &[u8], key: &[u8], prev_block: &[u8]) -> Vec<u8> {
        let decrypted = ecb_decrypt_single(block, key);
        utils::xor_bytes(&decrypted, prev_block)
    }

    pub fn cbc_encrypt(data: &[u8], key: &[u8], iv: Option<&[u8]>) -> Vec<u8> {
        let iv: &[u8] = iv.unwrap_or(&[0u8; 16]);
        let data = pkcs7_pad(data, 16);
        assert_eq!(&data.len() % 16, 0);
        let mut blocks: Vec<&[u8]> = vec![];
        blocks.push(iv);
        for chunk in data.chunks(16) {
            blocks.push(chunk);
        }
        let mut output: Vec<u8> = vec![];
        for window in blocks.windows(2) {
            if let [prev, curr] = window {
                let res = cbc_single_encrypt(curr, key, prev);
                output.extend_from_slice(&res);
            }
        }
        output
    }

    pub fn cbc_decrypt(data: &[u8], key: &[u8], iv: Option<&[u8]>) -> Vec<u8> {
        let iv: &[u8] = iv.unwrap_or(&[0u8; 16]);
        let mut blocks: Vec<&[u8]> = vec![];
        blocks.push(iv);
        for chunk in data.chunks(16) {
            blocks.push(chunk);
        }
        let mut output: Vec<u8> = vec![];
        for window in blocks.windows(2) {
            if let [prev, curr] = window {
                let res = cbc_single_decrypt(curr, key, prev);
                output.extend_from_slice(&res);
            }
        }
        pkcs7_unpad(&output)
    }

    #[derive(PartialEq, Eq, Debug)]
    pub enum Mode {
        Ecb,
        Cbc,
    }

    pub fn encryption_oracle(data: &[u8], keysize: usize) -> Mode {
        let num_chunks = data.len() / keysize;
        let chunks: Vec<Vec<u8>> = data
            .chunks(keysize)
            .take(num_chunks)
            .map(|c| c.to_vec())
            .collect();

        let mut sum = 0;
        for i in 0..chunks.len() {
            for j in i + 1..chunks.len() {
                if &chunks[i] == &chunks[j] {
                    sum += 1;
                }
            }
        }

        if sum > 0 {
            Mode::Ecb
        } else {
            Mode::Cbc
        }
    }

    pub fn random_aes_key() -> Vec<u8> {
        utils::generate_random_string(16).as_bytes().to_vec()
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

#[cfg(test)]
mod aes_tests {
    use super::aes::*;

    #[test]
    fn test_pkcs7_pad_shorter() {
        let data = "hello world".as_bytes();

        let pad = pkcs7_pad(data, 16);
        assert_eq!(pad.len(), 16);
        assert_eq!(pad[pad.len() - 1], 5);
        assert_eq!(pad.len() % 16, 0);
    }
    #[test]
    fn test_pkcs7_pad_equal() {
        let data = "hello world".as_bytes();

        let pad = pkcs7_pad(data, 11);
        assert_eq!(pad.len(), 11);
        assert_eq!(pad[pad.len() - 1], 'd' as u8); // not padded
    }
    #[test]
    fn test_pkcs7_pad_longer() {
        let data = "hello world hello world hello world".as_bytes();

        let pad = pkcs7_pad(data, 16);
        assert_eq!(pad.len(), 48);
        assert_eq!(pad[pad.len() - 1], 13);
        assert_eq!(pad.len() % 48, 0);
    }

    #[test]
    fn test_pkcs7_unpad() {
        let mut data = "hello world".as_bytes().to_vec();
        data.extend_from_slice(&[4, 4, 4, 4]);
        let data = &data[..];

        assert_eq!(pkcs7_unpad(data), "hello world".as_bytes());
    }
    #[test]
    fn test_pkcs7_unpad_no_pad() {
        let data = "hello world".as_bytes();

        assert_eq!(pkcs7_unpad(data), "hello world".as_bytes());
    }

    #[test]
    fn test_ecb_encrypt_decrypt() {
        let data = vec![123; 16];
        let key = "SASQUATCH JERSEY".as_bytes();
        let encrypted = ecb_encrypt(&data, key);
        let decrypted = ecb_decrypt(&encrypted, key);

        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_single_cbc_encrypt_decrypt() {
        let data = vec![123; 16];
        let key = "SASQUATCH JERSEY".as_bytes();
        let iv = vec![0u8; 16];
        let encrypted = cbc_single_encrypt(&data, key, &iv);
        let decrypted = cbc_single_decrypt(&encrypted, key, &iv);

        assert_eq!(encrypted.len(), 16);
        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_cbc_encrypt_decrypt() {
        let data = vec![123; 16];
        let key = "SASQUATCH JERSEY".as_bytes();
        let iv = vec![0u8; 16];
        let encrypted = cbc_encrypt(&data, key, Some(&iv));
        let decrypted = cbc_decrypt(&encrypted, key, Some(&iv));

        assert_eq!(data, decrypted);
    }
}
