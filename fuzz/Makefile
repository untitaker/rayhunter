AFL_TARGET_BIN=../target/release/fuzz-afl-main
# Download some default seeds from the internet
default-seeds.tar.gz:
	curl -L https://github.com/ZeroChaos-/rayhunter-traces/archive/refs/heads/main.tar.gz > ./default-seeds.tar.gz

default-seeds: default-seeds.tar.gz
	rm -rf seeds default-seeds
	mkdir -p default-seeds
	tar -C default-seeds -xvf default-seeds.tar.gz
	mv default-seeds/rayhunter-traces-main/*.qmdl default-seeds/
	rm -r default-seeds/rayhunter-traces-main

use-default-seeds: default-seeds build
	rm -rf seeds seeds-raw
	mkdir -p seeds-raw
	cargo build --release --bin qmdl-split
	for file in default-seeds/*.qmdl; do \
		basename=$$(basename "$$file" .qmdl); \
		QMDL_SPLIT_MAX_MESSAGES=10000 ../target/release/qmdl-split "seeds-raw/$$basename-" < "$$file"; \
	done
	cargo afl cmin -i seeds-raw -o seeds -T 8 -m none ${AFL_TARGET_BIN}
	rm -rf seeds-raw
.PHONY: use-default-seeds

# Build the fuzz target in release mode
build:
	cargo afl build --bin fuzz-afl-main --release
.PHONY: build

# Run fuzzer with single instance
fuzz: build
	cargo afl fuzz -i seeds -o findings ${AFL_TARGET_BIN}
.PHONY: fuzz

# Clean fuzzing artifacts
clean:
	rm -rf findings/
.PHONY: clean
