#!/bin/bash

# gather coverage

# llvm-cov
cargo llvm-cov --html --show-instantiations && \
mv ./target/llvm-cov/html ./outputs/llvm_cov && \
cargo clean

cargo llvm-cov --json | llvm-cov-pretty --output-dir ./outputs/llvm_cov_pretty && \
cargo clean

# tarpaulin
cargo tarpaulin  --ignore-tests --count --engine llvm --out html --force-clean && \
mv tarpaulin-report.html ./outputs && \
cargo clean

# MUST RUN MANUALLY with insecure docker settings:
# docker run -it --security-opt seccomp=unconfined tob_cov_test bash
# cargo tarpaulin  --ignore-tests --count --engine ptrace --out html --force-clean && \
# mv tarpaulin-report.html ./outputs && \
# cargo clean

# grcov llvm
export RUSTFLAGS="-Cinstrument-coverage" && \
cargo build && \
export LLVM_PROFILE_FILE="tob_test-%p-%m.profraw" && \
cargo test && \
grcov . -s . --binary-path ./target/debug/ -t html --branch --ignore-not-existing -o ./outputs/grcov_llvm && \
mkdir ./outputs/grcov_llvm_lcov && \
grcov . -s . --binary-path ./target/debug/ -t lcov --branch --ignore-not-existing -o ./outputs/grcov_llvm_lcov && \
genhtml -o ./outputs/grcov_llvm_lcov --show-details --highlight --ignore-errors source --legend ./outputs/grcov_llvm_lcov/lcov && \
cargo clean && \
find . -name '*.profraw' -exec rm '{}' \; && \
unset LLVM_PROFILE_FILE RUSTFLAGS

# grcov
export RUSTC_BOOTSTRAP=1
export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests -Cpanic=abort"
export RUSTDOCFLAGS="-Cpanic=abort"
cargo build && \
cargo test && \
grcov . -s . --binary-path ./target/debug/ -t html --branch --ignore-not-existing -o ./outputs/grcov
mkdir ./outputs/grcov_lcov && \
grcov . -s . --binary-path ./target/debug/ -t lcov --branch --ignore-not-existing -o ./outputs/grcov_lcov && \
genhtml -o ./outputs/grcov_lcov --show-details --highlight --ignore-errors source --legend ./outputs/grcov_lcov/lcov 