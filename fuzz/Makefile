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
		QMDL_SPLIT_MAX_MESSAGES=30000 ../target/release/qmdl-split "seeds-raw/$$basename-" < "$$file"; \
	done
	cargo afl cmin -i seeds-raw -o seeds -T 8 -m none ${AFL_TARGET_BIN}
	rm -rf seeds-raw
.PHONY: use-default-seeds

# Build the fuzz target in release mode
build:
	cargo afl build --bin fuzz-afl-main --release
.PHONY: build

fuzz: build
	cargo afl fuzz -i seeds -o findings ${AFL_TARGET_BIN}
.PHONY: fuzz

fuzz-main: build
	cargo afl fuzz -i seeds -o findings -M main ${AFL_TARGET_BIN}
.PHONY: fuzz-main

# Usage: make fuzz-secondary ID=1
fuzz-secondary: build
	@if [ -z "$(ID)" ]; then echo "Error: ID not set. Usage: make fuzz-secondary ID=1"; exit 1; fi
	cargo afl fuzz -i seeds -o findings -S secondary$(ID) ${AFL_TARGET_BIN}
.PHONY: fuzz-secondary

# Clean fuzzing artifacts
clean:
	rm -rf findings/
.PHONY: clean
