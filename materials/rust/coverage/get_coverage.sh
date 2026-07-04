#!/bin/bash

set -euo pipefail

# gather coverage

# llvm-cov
# ./outputs/llvm_cov/index.html
cargo llvm-cov --html --show-instantiations && \
mv ./target/llvm-cov/html ./outputs/llvm_cov && \
cargo clean

# ./outputs/llvm_cov_pretty/index.html
cargo llvm-cov --json --show-instantiations | llvm-cov-pretty --output-dir ./outputs/llvm_cov_pretty && \
cargo clean

# tarpaulin
# ./outputs/tarpaulin-report.html
cargo tarpaulin  --ignore-tests --count --engine llvm --out html --force-clean && \
mv tarpaulin-report.html ./outputs && \
cargo clean

# tarpaulin ptrace
# MUST RUN MANUALLY with insecure docker settings:
# docker run -it --security-opt seccomp=unconfined tob_cov_test bash
# cargo tarpaulin  --ignore-tests --count --engine ptrace --out html --force-clean && \
# mv tarpaulin-report.html ./outputs && \
# cargo clean

# grcov llvm
export RUSTFLAGS="-Cinstrument-coverage"
export LLVM_PROFILE_FILE="tob_test-%p-%m.profraw"
cargo test
# NOTE: LLVM source-based branch coverage (grcov's --branch) needs a nightly
# toolchain built with `-Zcoverage-options=branch`. On this stable toolchain it
# is silently ignored (0 branches), so we don't pass --branch here.
# ./outputs/grcov_llvm/index.html
grcov . -s . --binary-path ./target/debug/ -t html --ignore-not-existing -o ./outputs/grcov_llvm && \
grcov . -s . --binary-path ./target/debug/ -t lcov --ignore-not-existing -o ./outputs/grcov_llvm_lcov.info
# ./outputs/grcov_llvm_lcov/index.html
genhtml -o ./outputs/grcov_llvm_lcov --show-details --ignore-errors source --legend ./outputs/grcov_llvm_lcov.info
cargo clean
find . -name '*.profraw' -exec rm '{}' \;
unset LLVM_PROFILE_FILE RUSTFLAGS

# grcov with gcov - deprecated
# export RUSTC_BOOTSTRAP=1
# export CARGO_INCREMENTAL=0
# export RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests -Cpanic=abort"
# export RUSTDOCFLAGS="-Cpanic=abort"
# cargo test && \
# grcov . -s . --binary-path ./target/debug/ -t html --branch --ignore-not-existing -o ./outputs/grcov && \
# grcov . -s . --binary-path ./target/debug/ -t lcov --branch --ignore-not-existing -o ./outputs/grcov_lcov.info && \
# genhtml -o ./outputs/grcov_lcov --show-details --ignore-errors source --legend ./outputs/grcov_lcov.info