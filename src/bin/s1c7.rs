use cryptopals::common::{aes, utils};

fn main() {
    let cyphertext = utils::bytes_from_b64_file("samples/s1/7.txt");
    let key = "YELLOW SUBMARINE".as_bytes();

    let plaintext = String::from_utf8(aes::ecb_decrypt(&cyphertext, key)).unwrap();
    println!("{}", plaintext);
}
