use std::collections::HashMap;

use cryptopals::common::{aes, utils};

fn main() {
    let target_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let target_string = utils::b64_to_bytes(target_string);
    let random_key = &aes::random_aes_key();

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
    for target_chunk in target_string.chunks(blocksize) {
        for index in 1..=blocksize {
            let mut local_decrypted: Vec<u8> = vec![];
            local_decrypted.extend(&decrypted[block_offset * blocksize..]);

            let table = build_rainbow_table(blocksize, &random_key, &local_decrypted);

            let mut test_text = vec!['A' as u8; blocksize - index];
            test_text.extend(target_chunk);
            let cyphertext = aes::ecb_encrypt(&test_text, random_key);

            if let Some(res) = table.get(&cyphertext[0..blocksize]) {
                decrypted.push(*res);
                print!("{}", *res as char);
            } else {
                break;
            }
        }
        block_offset += 1;
    }
    println!("\nDone!\n{}", String::from_utf8_lossy(&decrypted));
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
