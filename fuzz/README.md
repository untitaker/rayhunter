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

## Default seeds

`make default-seeds use-default-seeds` downloads some PCAPs from the internet,
splits them up into individual messages, and applies random sampling to
eliminate most of the data. This means that `use-default-seeds` is not
deterministically generating the same corpus everytime.

The problem that sampling aims to solve is that the input data is too much.
`afl cmin` seems to be broken and always generates an empty directory (not sure
why). The other issue is that even before `cmin` can run, the default seeds can
consume all inodes on the given machine.
