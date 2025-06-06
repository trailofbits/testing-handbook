export CARGO_LLVM_COV_TARGET_DIR=/root/handbook/rust/cargo-fuzz/fuzz/target
export LLVM_PROFILE_FILE="$CARGO_LLVM_COV_TARGET_DIR/fuzz-%p-%8m.profraw"

cd fuzz/
cargo +nightly fuzz run fuzz_divide
cargo +nightly fuzz run fuzz_divide -- -runs=0 corpus/fuzz_divide
cargo llvm-cov report --profile release --target x86_64-unknown-linux-gnu
