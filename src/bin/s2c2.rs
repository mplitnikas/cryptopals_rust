use cryptopals::common::{aes, caesar, utils};
use std::{convert::TryInto, iter::once};

fn main() {
    // put these in common::aes
    // use to read s2/10.txt, key YELLOW SUBMARINE
    let data = vec![0u8; 32];
    let key = "YELLOW SUBMARINE".as_bytes().try_into().unwrap();
    let res = aes::cbc_decrypt(&data, key, None);
    println!("output {:?}", res);
}
