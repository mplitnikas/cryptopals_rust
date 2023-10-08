use cryptopals::common::{aes, utils};
use rand::{random, Rng};

fn main() {
    let rounds = 100;
    for _ in 0..rounds {
        let data = vec!["A"; 50].join("");
        let data = data.as_bytes();
        let (cyphertext, use_cbc) = encrypt_with_random_mode(data);
        let cipher_mode = aes::encryption_oracle(&cyphertext, 16);
        assert_eq!(cipher_mode == aes::Mode::Cbc, use_cbc);
    }
    println!("successfully tested {rounds} times");
}

fn encrypt_with_random_mode(data: &[u8]) -> (Vec<u8>, bool) {
    let key = &aes::random_aes_key();
    let mut rnd = rand::thread_rng();

    let mut plaintext = vec![];
    plaintext.extend(utils::generate_random_string(rnd.gen_range(5..=10)).as_bytes());
    plaintext.extend(data);
    plaintext.extend(utils::generate_random_string(rnd.gen_range(5..=10)).as_bytes());

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
    (cyphertext, use_cbc)
}
