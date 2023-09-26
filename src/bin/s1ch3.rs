use cryptopals::caesar_tools::caesar;
use cryptopals::common::utils;

fn main() {
    let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let bytes = utils::hex_to_bytes(input);
    let (output, chr, score) = caesar::find_single_byte_xor_decode(&bytes);

    println!("out: {}", output);
    println!("chr: {}", chr as char);
    println!("score: {score}");
}
