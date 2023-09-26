use cryptopals::common::{aes, caesar, utils};

fn main() {
    let lines = utils::lines_from_b64_file("samples/s1/8.txt");

    // key is always 16 bytes
    // check each line for hamming dist between 16-byte blocks
    // whichever is lowest is probably the one
    // is the key still "YELLOW SUBMARINE" ?

    let keysize = 16;
    let mut best_score = 0;
    let mut best_line: Vec<u8> = vec![];
    for data in lines {
        let chunks: Vec<Vec<u8>> = data.chunks(keysize).take(15).map(|c| c.to_vec()).collect();

        let mut sum = 0;
        for i in 0..chunks.len() {
            for j in i + 1..chunks.len() {
                if &chunks[i] == &chunks[j] {
                    sum += 1;
                }
            }
        }
        if sum > best_score {
            best_score = sum;
            best_line = data;
        }
    }
    println!("BEST line {}", String::from_utf8_lossy(&best_line));

    // let decrypted = aes::aes_ecb_decrypt(&best_line, "YELLOW SUBMARINE".as_bytes());
    // let decrypted = String::from_utf8(decrypted).unwrap();
    // println!("tried decryption: {}", decrypted);

    // println!(
    //     "cyphertexts {:?}",
    //     cyphertexts
    //         .iter()
    //         .map(|x| String::from_utf8_lossy(x))
    //         .collect::<String>()
    // );
}

fn is_ecb(data: &[u8]) -> bool {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_ecb() {
        let data = &['a' as u8; 64][..];
        let enc = aes::aes_ecb_encrypt(data, "YELLOW SUBMARINE".as_bytes());
        println!("encrypted {:?}", enc);
        assert!(is_ecb(&enc));
    }
}
