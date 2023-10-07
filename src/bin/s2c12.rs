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

    let table = build_rainbow_table(blocksize, random_key);
    let mut test_text = vec!['A' as u8; blocksize - 1];
    test_text.extend(target_string);
    let cyphertext = aes::ecb_encrypt(&test_text, random_key);
    if let Some(res) = table.get(&cyphertext[0..blocksize]) {
        println!("found byte {}", *res as char);
    } else {
        println!("not found?");
    }

    // Knowing the block size, craft an input block that is exactly 1
    // byte short (for instance, if the block size is 8 bytes, make
    // "AAAAAAA"). Think about what the oracle function is going to put in
    // that last byte position.
    //
    // Make a dictionary of every possible last byte by feeding
    // different strings to the oracle; for instance, "AAAAAAAA",
    // "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
    //
    // Match the output of the one-byte-short input to one of the
    // entries in your dictionary. You've now discovered the first
    // byte of unknown-string.
    //
    // Repeat for the next byte.
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

fn build_rainbow_table(blocksize: usize, key: &[u8]) -> HashMap<Vec<u8>, u8> {
    let mut table = HashMap::new();
    let text = vec!['A' as u8; blocksize - 1];

    for byte in 0..=255 {
        let mut plaintext = text.clone();
        plaintext.extend([byte]);
        let cyphertext = aes::ecb_encrypt(&plaintext, key);

        table.insert(cyphertext, byte);
    }

    table
}
