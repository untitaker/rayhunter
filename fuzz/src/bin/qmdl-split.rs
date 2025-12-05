use std::io::{self, Read};
use std::fs;
use std::env;
use std::collections::HashSet;
use xxhash_rust::xxh3::xxh3_64;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <output-prefix> < input.qmdl", args[0]);
        eprintln!("Example: {} seeds/myfile- < default-seeds/myfile.qmdl", args[0]);
        eprintln!("Creates: seeds/myfile-000000.qmdl, seeds/myfile-000001.qmdl, ...");
        std::process::exit(1);
    }

    let mut data = Vec::new();
    io::stdin().read_to_end(&mut data).expect("Failed to read stdin");

    let prefix = &args[1];

    if let Some(parent) = std::path::Path::new(&prefix).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).expect("Failed to create output directory");
        }
    }

    let mut message_count = 0;
    let mut seen_hashes = HashSet::new();
    let mut duplicates_skipped = 0;

    fuzz::fuzz_qmdl_split(&data, |container_data| {
        let hash = xxh3_64(container_data);

        // Skip duplicate files to keep test corpus small. This is important because the amount of
        // output files can easily reach the inode limit.
        if seen_hashes.insert(hash) {
            let filename = format!("{}{:06}.qmdl", prefix, message_count);
            fs::write(&filename, container_data).expect("Failed to write message file");
            message_count += 1;
        } else {
            duplicates_skipped += 1;
        }
    });

    eprintln!("Split {} unique messages with prefix {:?} ({} duplicates skipped)",
              message_count, prefix, duplicates_skipped);
}
