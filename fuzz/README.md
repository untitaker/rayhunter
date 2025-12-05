# Fuzzing rayhunter-check

AFL fuzzing for QMDL/PCAP parsing and analysis. Tests both parsers and all default analyzers against malformed inputs.

## Usage

Install cargo-afl:
```bash
cargo install afl
```

Initialize seed corpus and build:
```bash
make default-seeds      # Download seed corpus from rayhunter-traces
make use-default-seeds  # Minimize seeds into seeds/ directory
make build              # Build fuzz target in release mode
```

Run fuzzer:
```bash
make fuzz  # Run fuzzer with single instance
```

Crashes will be in `findings/crashes/`.

Clean fuzzing artifacts:
```bash
make clean  # Remove findings/ directory
```
