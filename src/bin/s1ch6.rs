use cryptopals::caesar_tools::caesar;
use cryptopals::common::utils;
use std::error::Error;
use std::fs;

fn main() -> Result<(), Box<dyn Error>> {
    let file = fs::read("samples/s1/6.txt")?;
    // there has to be a better way to do this
    let file: Vec<u8> = file.iter().filter(|&c| *c != '\n' as u8).cloned().collect();
    let bytes = utils::b64_to_bytes(&String::from_utf8(file).unwrap());

    let possible_keysizes = find_best_keysizes(&bytes);
    println!("{:?}", possible_keysizes);

    let mut best_score = 0.0;
    let mut best_key: Vec<u8> = vec![];
    for keysize in possible_keysizes {
        let chunks = transpose_by_keysize(&bytes, keysize);
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

fn find_best_keysizes(data: &[u8]) -> Vec<usize> {
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

    println!("all best keysizes {:?}", best_keysizes);
    best_keysizes[..5].to_vec().iter().map(|x| x.0).collect()
}

fn transpose_by_keysize(data: &[u8], keysize: usize) -> Vec<Vec<u8>> {
    let mut output_vec: Vec<Vec<u8>> = vec![Vec::new(); keysize];
    data.iter()
        .zip((0..keysize).cycle())
        .for_each(|(&byte, index)| {
            output_vec[index].push(byte);
        });

    output_vec
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
        let keysizes = find_best_keysizes(&data);

        assert_eq!(keysizes[0], 5);
    }

    #[test]
    fn test_split_keysize_2() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let split = transpose_by_keysize(&data, 2);

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
        let split = transpose_by_keysize(&data, 5);

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
        let split = transpose_by_keysize(&data, 11);

        assert_eq!(split.len(), 11);
        for i in 0..11 {
            assert!(split[i].iter().all(|&x| x == i as u8));
        }
    }
}
