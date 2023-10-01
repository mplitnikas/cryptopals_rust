use cryptopals::common::{aes, utils};
use std::convert::TryInto;

fn main() {
    let data = utils::bytes_from_b64_file("samples/s2/10.txt");
    let key = "YELLOW SUBMARINE".as_bytes().try_into().unwrap();
    let res = aes::cbc_decrypt(&data, key, None);
    println!("output\n{}", String::from_utf8(res).unwrap());
}
