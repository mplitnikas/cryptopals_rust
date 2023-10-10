use cryptopals::common::{aes, utils};
use rand::Rng;
use std::collections::HashMap;

fn main() {
    let mut rnd = rand::thread_rng();
    let random_prefix = utils::generate_random_string(rnd.gen_range(2..1024))
        .as_bytes()
        .to_vec();
    let target_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let target_string = utils::b64_to_bytes(target_string).to_vec();
    let random_key = &aes::random_aes_key();

    let encrypt_message = |controlled_text: &[u8]| -> Vec<u8> {
        let mut plaintext = vec![];
        plaintext.extend(&random_prefix);
        plaintext.extend_from_slice(&controlled_text);
        plaintext.extend(&target_string);
        aes::ecb_encrypt(&plaintext, &random_key)
    };

    let mut blocksize = 0;
    let mut prefix_offset = 0;
    'outer: for size in 2..=40 {
        let controlled_text = vec!["A"; 120].join("").as_bytes().to_vec();
        let cyphertext = encrypt_message(&controlled_text);

        let blocks: Vec<&[u8]> = cyphertext.chunks(size).collect();
        for (i, window) in blocks.windows(2).enumerate() {
            if let [prev, curr] = window {
                if prev == curr {
                    blocksize = size;
                    prefix_offset = i;
                    assert_eq!(aes::encryption_oracle(&cyphertext, size), aes::Mode::Ecb);
                    println!("using ECB with blocksize {blocksize} and offset {prefix_offset}");
                    break 'outer;
                }
            }
        }
    }

    // once we have the offset, we know the target string starts one block (?) later
    // and the prefix ends 0 to blocksize bytes earlier
    // we do need the exact prefix length, since we'll need to tune the controlled input with one-byte precision

    // number of bytes that get "eaten up" by odd-length prefix block
    let mut byte_offset = 0;
    'outer: for size in 0..blocksize {
        let controlled_text = vec!["A"; (blocksize * 2) + size]
            .join("")
            .as_bytes()
            .to_vec();
        let cyphertext = encrypt_message(&controlled_text);

        let blocks: Vec<&[u8]> = cyphertext.chunks(blocksize).collect();
        for window in blocks.windows(2) {
            if let [prev, curr] = window {
                if prev == curr {
                    byte_offset = size;
                    println!("found byte offset of {byte_offset}");
                    // TODO delete these asserts, we "shouldn't" have access to plaintext
                    // assert!(plaintext[prefix_offset * blocksize - byte_offset - 1] != 'A' as u8);
                    // assert!(plaintext[prefix_offset * blocksize - byte_offset] == 'A' as u8);
                    // assert!(plaintext[prefix_offset * blocksize + blocksize * 2 - 1] == 'A' as u8);
                    // assert!(plaintext[prefix_offset * blocksize + blocksize * 2] != 'A' as u8);
                    break 'outer;
                }
            }
        }
    }

    // controlled text starts at (prefix_offset * blocksize - byte_offset)
    let mut decrypted: Vec<u8> = vec![];
    // loop through ???
    // controlled string is always at least byte_offset long
    // plus 0..blocksize depending on iteration
    // instead of going chunk by chunk like before, can we add decrypted to controlled_text?
    // downside is that the keys in the rainbow table get arbitrarily long
    // nah let's do like before and iterate thru chunks
    'outer: for block_index in 0.. {
        for byte_index in 1..=blocksize {
            let target_offset = (prefix_offset * blocksize) + (block_index * blocksize);
            let target_block_range = target_offset..target_offset + blocksize;

            let controlled_text_len = byte_offset + blocksize - byte_index;
            let controlled_text = vec!["A"; controlled_text_len].join("").as_bytes().to_vec();
            let mut table_text = controlled_text.clone();
            table_text.extend(&decrypted);
            // after first iteration this needs to be AAAAAAR*, AAAAARo*, etc
            // controlled text for building table and for actual decryption are different
            // building table needs decrypted appended to it
            // cracking next char needs to just be AAAA
            // probably pass decrypted into table builder and chop into blocks with same range
            // will need to split range down into block_index, blocksize, etc
            // since indexing into decrypted string and cyphertext start at different points
            // what is the index diff btwn controlled text and target_offset?
            // should be prefix_offset * blocksize - byte_offset ???

            let table = build_rainbow_table(&table_text, &target_block_range, encrypt_message);

            let cyphertext = encrypt_message(&controlled_text);

            if let Some(res) = table.get(&cyphertext[target_block_range]) {
                decrypted.push(*res);
                println!("{}", *res as char);
            } else {
                break 'outer;
            }
        }
    }
    println!("\nDone!\n{}", String::from_utf8_lossy(&decrypted));

    fn build_rainbow_table<F>(
        controlled_text: &Vec<u8>,
        offset: &std::ops::Range<usize>,
        encrypt_function: F,
    ) -> HashMap<Vec<u8>, u8>
    where
        F: Fn(&[u8]) -> Vec<u8>,
    {
        let mut table = HashMap::new();

        for byte in 0..=255 {
            let mut plaintext = controlled_text.clone();
            plaintext.extend([byte]);
            let cyphertext = encrypt_function(&plaintext);

            table.insert(cyphertext[offset.clone()].to_vec(), byte);
        }

        table
    }
}

// redo how we build the rainbow table - we don't have access to the key etc
// instead call out to the encrypt fn
// and look at the blocks at the correct offset to build up a table
// first block is ez because it's AAAAAAAAx
// after that the padding contained will be from the output of decrypted bytes
// though controlled string will still change in length the same way
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
