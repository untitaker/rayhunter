use afl::fuzz;

fn main() {
    fuzz!(|data: &[u8]| {
        fuzz::fuzz_differential(data);
    });
}
