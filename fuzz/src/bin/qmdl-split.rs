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
        eprintln!("Set QMDL_SPLIT_MAX_MESSAGES=1000 to limit output (default: no limit)");
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

    let max_messages = env::var("QMDL_SPLIT_MAX_MESSAGES")
        .ok()
        .and_then(|s| s.parse::<usize>().ok());

    // First pass: count unique messages
    let mut seen_hashes = HashSet::new();
    let mut unique_hashes = Vec::new();

    fuzz::fuzz_qmdl_split(&data, |container_data| {
        let hash = xxh3_64(container_data);
        if seen_hashes.insert(hash) {
            unique_hashes.push(hash);
        }
    });

    let unique_count = unique_hashes.len();

    // Calculate sampling rate
    let sample_rate = if let Some(max) = max_messages {
        if unique_count > max {
            max as f64 / unique_count as f64
        } else {
            1.0
        }
    } else {
        1.0
    };

    // Second pass: write messages with sampling
    let mut message_count = 0;
    let mut current_unique_idx = 0;
    let mut total_messages = 0;
    let mut duplicates_skipped = 0;
    seen_hashes.clear();

    fuzz::fuzz_qmdl_split(&data, |container_data| {
        total_messages += 1;
        let hash = xxh3_64(container_data);

        if seen_hashes.insert(hash) {
            // This is a unique message
            let should_write = if sample_rate < 1.0 {
                // Use hash to deterministically decide if we write this one
                (hash as f64 / u64::MAX as f64) < sample_rate
            } else {
                true
            };

            if should_write {
                let filename = format!("{}{:06}.qmdl", prefix, message_count);
                fs::write(&filename, container_data).expect("Failed to write message file");
                message_count += 1;
            }
            current_unique_idx += 1;
        } else {
            duplicates_skipped += 1;
        }
    });

    eprintln!("Split {} unique messages with prefix {:?} (from {} total, {} duplicates, sample rate: {:.2})",
              message_count, prefix, total_messages, duplicates_skipped, sample_rate);
}
