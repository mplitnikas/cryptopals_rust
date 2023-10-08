use std::collections::HashMap;

use cryptopals::common::{aes, caesar, utils};
use rand::{random, Rng};

fn main() {
    let target_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let target_string = utils::b64_to_bytes(target_string);
    let random_key = &generate_random_string(16).as_bytes().to_vec();

    let mut blocksize = 0;
    for size in 2..40 {
        let controlled_text = vec!["A"; size * 2].join("").as_bytes().to_vec();
        let mut plaintext = vec![];
        plaintext.extend(controlled_text);
        plaintext.extend(&target_string);
        let cyphertext = aes::ecb_encrypt(&plaintext, &random_key);

        if &cyphertext[0..size] == &cyphertext[size..size * 2] {
            blocksize = size;
            assert_eq!(aes::encryption_oracle(&cyphertext, size), aes::Mode::Ecb);
            println!("using ECB with blocksize {size}");
            break;
        }
    }

    let target_string = aes::pkcs7_pad(&target_string, blocksize);

    let mut decrypted: Vec<u8> = vec![];
    let mut block_offset = 0;
    loop {
        for index in 1..=blocksize {
            let target_chunk =
                &target_string[block_offset * blocksize..block_offset * blocksize + blocksize];

            let mut local_decrypted: Vec<u8> = vec![];
            local_decrypted.extend(&decrypted[block_offset * blocksize..]);

            let table = build_rainbow_table(blocksize, &random_key, &local_decrypted);
            let mut test_text = vec!['A' as u8; blocksize - index];
            test_text.extend(target_chunk);
            let cyphertext = aes::ecb_encrypt(&test_text, random_key);
            if let Some(res) = table.get(&cyphertext[0..blocksize]) {
                decrypted.push(*res);
                println!("{}", String::from_utf8_lossy(&decrypted));
            } else {
                println!(
                    "==============done: {}",
                    String::from_utf8_lossy(&decrypted)
                );
                // break;
            }
        }
        block_offset += 1;
    }
}

fn build_rainbow_table(blocksize: usize, key: &[u8], known_block: &[u8]) -> HashMap<Vec<u8>, u8> {
    let mut table = HashMap::new();
    let mut text;
    let pad_len = blocksize.saturating_sub(known_block.len() + 1);
    text = vec!['A' as u8; pad_len];
    text.extend_from_slice(&known_block);

    for byte in 0..=255 {
        let mut plaintext = text.clone();
        plaintext.extend([byte]);
        let cyphertext = aes::ecb_encrypt(&plaintext, key);

        table.insert(cyphertext, byte);
    }

    table
}

fn generate_random_string(length: usize) -> String {
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
