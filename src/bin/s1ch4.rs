use cryptopals::common::{caesar, utils};
use std::error::Error;
use std::fs;

fn main() -> Result<(), Box<dyn Error>> {
    let file = fs::read("samples/s1/4.txt")?;
    let lines = file.split(|&c| c == '\n' as u8);

    let mut max_score = 0.0;
    let mut xor_char: u8 = 0;
    let mut output_str: String = "".to_string();
    for line in lines {
        let hex = String::from_utf8(line.to_vec())?;
        let bytes = utils::hex_to_bytes(&hex);
        let (output, chr, score) = caesar::find_single_byte_xor_decode(&bytes);
        if score > max_score {
            max_score = score;
            xor_char = chr;
            output_str = output;
        }
    }
    println!("output {output_str}");
    println!("XOR'd with {}", xor_char as char);
    println!("score {max_score}");
    Ok(())
}
