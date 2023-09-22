use cryptopals::common::utils::{bytes_to_hex, hex_to_bytes, xor_bytes};

fn main() {
    let hex1 = "1c0111001f010100061a024b53535009181c";
    let hex2 = "686974207468652062756c6c277320657965";
    let expected = "746865206b696420646f6e277420706c6179";

    let xord = bytes_to_hex(&xor_bytes(&hex_to_bytes(hex1), &hex_to_bytes(hex2)));
    println!("xor: {}", xord);
    println!("exp: {}", expected);
}
