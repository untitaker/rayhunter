use std::io::{self, Read};

fn main() {
    // Read all input from stdin
    let mut data = Vec::new();
    io::stdin().read_to_end(&mut data).expect("Failed to read stdin");

    fuzz::fuzz_qmdl(&data);
}
