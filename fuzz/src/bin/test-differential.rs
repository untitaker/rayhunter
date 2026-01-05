use std::io::{self, Read};

fn main() {
    let mut data = Vec::new();
    io::stdin().read_to_end(&mut data).expect("Failed to read stdin");

    fuzz::fuzz_differential(&data);

    println!("OK - parsers match");
}
