use std::io::{self, Read};
use std::fs;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <output-prefix> < input.qmdl", args[0]);
        eprintln!("Example: {} seeds/myfile- < default-seeds/myfile.qmdl", args[0]);
        eprintln!("Creates: seeds/myfile-000000.qmdl, seeds/myfile-000001.qmdl, ...");
        std::process::exit(1);
    }

    // Read all input from stdin
    let mut data = Vec::new();
    io::stdin().read_to_end(&mut data).expect("Failed to read stdin");

    // Get prefix from first argument
    let prefix = &args[1];

    // Create parent directory once before writing any files
    if let Some(parent) = std::path::Path::new(&prefix).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).expect("Failed to create output directory");
        }
    }

    let mut message_count = 0;

    fuzz::fuzz_qmdl_split(&data, |container_data| {
        let filename = format!("{}{:06}.qmdl", prefix, message_count);
        fs::write(&filename, container_data).expect("Failed to write message file");
        message_count += 1;
    });

    eprintln!("Split {} messages with prefix {:?}", message_count, prefix);
}
