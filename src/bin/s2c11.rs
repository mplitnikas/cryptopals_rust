use cryptopals::common::aes;
use rand::{random, Rng};

fn main() {
    for _ in 0..10 {
        let data = vec!["A"; 50].join("");
        let data = data.as_bytes();
        let (cyphertext, use_cbc) = encrypt_with_random_mode(data);
        let cipher_mode = aes::encryption_oracle(&cyphertext);
        // println!("detecting {}", if use_cbc { "cbc" } else { "ecb" });
        assert_eq!(cipher_mode == "cbc", use_cbc);
        // println!("correct!");
        // println!("");
    }
}

fn encrypt_with_random_mode(data: &[u8]) -> (Vec<u8>, bool) {
    let key = generate_random_string(16);
    let key = key.as_bytes();
    let mut rnd = rand::thread_rng();

    let mut plaintext = vec![];
    plaintext.extend(generate_random_string(rnd.gen_range(5..=10)).as_bytes());
    plaintext.extend(data);
    plaintext.extend(generate_random_string(rnd.gen_range(5..=10)).as_bytes());

    // println!("{:?}", String::from_utf8(plaintext.to_vec()).unwrap());
    let use_cbc = random(); // true->cbc, false->ecb

    let cyphertext: Vec<u8>;
    if use_cbc {
        let mut iv = vec![]; // create randomized iv block
        for _ in 0..16 {
            iv.push(rnd.gen_range(0..=255));
        }
        cyphertext = aes::cbc_encrypt(&plaintext, key, Some(&iv));
    } else {
        cyphertext = aes::ecb_encrypt(&plaintext, key);
    }
    // for chunk in cyphertext.chunks(16) {
    //     println!("{:?}", chunk);
    // }
    (cyphertext, use_cbc)
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
