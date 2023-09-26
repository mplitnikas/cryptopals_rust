use cryptopals::common::utils;

fn main() {
    let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let b64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    let bytes = utils::hex_to_bytes(hex);
    let res = utils::bytes_to_b64(&bytes);

    println!("out: {}", res);
    println!("exp: {}", b64);
}
