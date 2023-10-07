use cryptopals::common::{caesar, utils};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let bytes = utils::bytes_from_b64_file("samples/s1/6.txt");

    let possible_keysizes = caesar::find_best_keysizes(&bytes);

    let mut best_score = 0.0;
    let mut best_key: Vec<u8> = vec![];
    for keysize in possible_keysizes {
        let chunks = caesar::transpose_by_keysize(&bytes, keysize);
        let key_bytes = chunks
            .iter()
            .map(|chunk| caesar::find_single_byte_xor_decode(chunk))
            .map(|(_, byte, score)| (byte, score))
            .collect::<Vec<(u8, f32)>>();

        let score: f32 = key_bytes.iter().map(|(_byte, score)| score).sum();
        if score > best_score {
            best_score = score;
            best_key = key_bytes
                .iter()
                .map(|(byte, _score)| byte)
                .copied()
                .collect();
        }
    }
    let decoded = utils::xor_bytes(&bytes, &best_key);
    println!("{}", &String::from_utf8(decoded)?);
    println!("decoded with key |{}|", String::from_utf8_lossy(&best_key));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_best_keysize() {
        let data: Vec<u8> = vec!['a', 'b', 'c', 'd', 'e']
            .iter()
            .map(|&x| x as u8)
            .cycle()
            .take(500)
            .collect();
        let keysizes = caesar::find_best_keysizes(&data);

        assert_eq!(keysizes[0], 5);
    }

    #[test]
    fn test_split_keysize_2() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let split = caesar::transpose_by_keysize(&data, 2);

        println!("split: {:?}", split);
        // panic!();
        assert_eq!(split.len(), 2);
        assert!(!split[0].is_empty());
        assert!(split[0].iter().all(|x| x % 2 == 1));
        assert!(split[1].iter().all(|x| x % 2 == 0));
    }

    #[test]
    fn test_split_keysize_5() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let split = caesar::transpose_by_keysize(&data, 5);

        println!("split: {:?}", split);
        assert_eq!(split.len(), 5);
        assert!(!split[0].is_empty());
        for i in 1..=4 {
            assert!(split[i - 1].iter().all(|x| x % 5 == i as u8))
        }
        assert!(split[4].iter().all(|x| x % 5 == 0));
    }

    #[test]
    fn test_split_keysize_big() {
        let data: Vec<u8> = (0..11).cycle().take(300).collect();
        let split = caesar::transpose_by_keysize(&data, 11);

        assert_eq!(split.len(), 11);
        for i in 0..11 {
            assert!(split[i].iter().all(|&x| x == i as u8));
        }
    }
}
