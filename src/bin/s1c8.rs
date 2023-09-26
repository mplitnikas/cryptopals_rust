use cryptopals::common::utils;

fn main() {
    let lines = utils::lines_from_b64_file("samples/s1/8.txt");

    let keysize = 16;
    let mut best_score = 0;
    let mut best_line: Vec<u8> = vec![];
    for data in lines {
        let chunks: Vec<Vec<u8>> = data.chunks(keysize).take(15).map(|c| c.to_vec()).collect();

        let mut sum = 0;
        for i in 0..chunks.len() {
            for j in i + 1..chunks.len() {
                if &chunks[i] == &chunks[j] {
                    sum += 1;
                }
            }
        }
        if sum > best_score {
            best_score = sum;
            best_line = data;
        }
    }
    println!("BEST line {}", String::from_utf8_lossy(&best_line));
}
