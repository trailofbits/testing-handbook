---
title: "Dynamic analysis"
slug: dynamic-analysis
weight: 20
---

# Rust dynamic analysis

There are two categories of dynamic analysis: fuzz testing and "standard" testing, like unit and functional testing.

In this chapter, we will focus on standard testing. This is the basic level of testing that every project should have implemented. While basic, standard testing can be built up with a lot of security-wise improvements. To read about Rust fuzzing, see the [Rust fuzzing chapter]({{% relref "/docs/fuzzing/rust" %}}) of this handbook.

The standard tool for executing unit tests for Rust codebases is [`cargo test`](https://doc.rust-lang.org/cargo/commands/cargo-test.html). The basic setup and usage of the tool is well known, so we will skip the introduction. You can also try [`cargo nextest`](https://nexte.st/index.html), a new test runner.

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn true_dilemma() {
        assert_ne!(true, false);
    }
}
```

Once you have the unit tests written and all of them pass, let’s improve on them.

{{< hint info >}}
To speed up the CI pipeline, use [`cargo-line-test`](https://github.com/trailofbits/cargo-line-test). It executes only the tests that exercise modified files and lines. It may be especially useful when using advanced but slow testing methods described later in this section.
{{< /hint >}}

## Randomization

### Test order shuffling

Tests that depend on a global state or have dependencies between each other may be buggy but pass when executed normally. By default, tests are executed in multiple threads and in (mostly) alphabetical order. Therefore, they are quasi-deterministic.

To find problematic test dependencies, increase the entropy of execution. Ideally, run tests without parallel execution in a random order:

```sh
cargo +nightly test -- -Z unstable-options --test-threads 1 --shuffle
```

Note that random order shuffling is [not possible with `nextest`](https://github.com/nextest-rs/nextest/discussions/1784).

{{< hint danger >}}
This approach is not scalable and should not be extensively used in CI/CD pipelines. Instead, start such tests manually once in a while.
{{< /hint >}}

Execute the `cargo test` command above multiple times. If any run reports a failed test, use the displayed "shuffle seed" to reliably repeat the error.

{{< details "Example to try: cargo test shuffle seed" >}}

The tests below fail randomly when run with cargo test. To get a reproducible failure, run this:

```sh
cargo +nightly test -- -Z unstable-options --test-threads 1 --shuffle-seed 1337
```

```rust
fn main() { println!("Hello, world!"); }

static mut GLOB_VAR: i32 = 2;

unsafe fn global_var_set(arg: i32) {
    GLOB_VAR = arg;
}

#[cfg(test)]
mod tests {
    use crate::{GLOB_VAR, global_var_set};

    #[test]
    fn a_true_dilemma() {
        unsafe { assert_eq!(GLOB_VAR, 2); }
        unsafe { global_var_set(5); }
        unsafe { assert_eq!(GLOB_VAR, 5); }
        assert_ne!(true, false);
    }

    #[test]
    fn not_true_dilemma() {
        unsafe { assert_eq!(GLOB_VAR, 2); }
        assert_ne!(true, false);
    }
}
```

{{< /details >}}

### Features randomization

Rust code supports conditional compilation via [Cargo features](https://doc.rust-lang.org/cargo/reference/features.html). Ideally, tests would cover all possible versions of a program. To ensure that, we need to run tests against all possible (or supported) combinations of features.

For this task, use [`cargo hack`](https://github.com/taiki-e/cargo-hack). Start with testing your code against all the features taken separately, then combine multiple features in one run:

{{< tabs "cargo-hack" >}}
{{< tab "Shell" >}}

```sh
cargo +nightly install cargo-hack --locked
cargo hack test --each-feature
cargo hack test --feature-powerset --depth 2
```

{{< /tab >}}
{{< tab "CI" >}}

```yaml
- uses: taiki-e/install-action@6da51af62171044932d435033daa70a0eb3383ba
  with:
    tool: cargo-hack
- run: cargo hack test --feature-powerset --depth 2 --workspace
```

{{< /tab >}}
{{< /tabs >}}

{{< hint info >}}
Look for the info: running string in the test output to check what features were used.

Use the `--print-command-list` option for a dry run.

Use the `--keep-going` option to skip over compilation failures.
{{< /hint >}}

{{< details "Example to try: cargo hack with three features" >}}

The test below passes when run with the cargo test command. It also passes with `cargo hack test --each-feature`. To find the code path that makes the test fail, run this:

```sh
cargo hack test --feature-powerset --depth 2
```

```toml
# Cargo.toml
[features]
fone = []
ftwo = []
fthree = []
```

```rust
fn main() { println!("Hello, world!"); }

#[allow(unreachable_code)]
fn feature_one() -> i32 {
    #[cfg(all(feature = "fone", feature = "fthree", not(feature = "ftwo")))]
    {
        return 3;
    }
    #[cfg(feature = "fone")] {
        return 1;
    }
    #[cfg(feature = "ftwo")] {
        return 2;
    }
    return 0;
}


#[cfg(test)]
mod tests {
    use crate::{feature_one};

    #[test]
    fn feature_test1() {
        let z = feature_one();
        assert!(z < 3);
    }
}
```

{{< /details >}}

## Integer overflows

Most integer overflows are detected at runtime in debug builds (or when the [`overflow-checks` flag](https://doc.rust-lang.org/rustc/codegen-options/index.html#overflow-checks) is set). There is also [Clippy’s `arithmetic_side_effects` lint](https://rust-lang.github.io/rust-clippy/master/index.html#arithmetic_side_effects), which can statically find possible overflows.

However, neither of these approaches detects overflows in explicit casts. To make your tests detect overflows in `expr as T` expressions, you can use the [`cast_checks`](https://github.com/trailofbits/cast_checks) tool.

Install it by adding the following to your project’s `Cargo.toml` file:

```toml
[dependencies]
cast_checks = "0.1.6"
```

Then, mark functions where you suspect overflows may be possible with `#[cast_checks::enable]` and run tests as usual.

Alternatively, enable the inner attributes feature with `#![feature(custom_inner_attributes, proc_macro_hygiene)]` and put the `#![cast_checks::enable]` attribute in relevant modules.

{{< details "Example to try: cast_checks in action" >}}
In this example, the `int_overflow_simple` test always passes, as arithmetic overflows are detected with standard overflow checks. However, to detect overflow in the `int_overflow_in_cast` test, `cast_checks` needs to be used.

```rust
#![feature(custom_inner_attributes, proc_macro_hygiene)]

fn main() { println!("Hello, world!"); }

mod overflow_lib {
    #![cast_checks::enable]

    pub(crate) fn do_overflow(a: i32) -> i32 {
        return a * 8;
    }

    pub(crate) fn as_u16(z: i32) -> u16 {
        z as u16
    }
}

#[cfg(test)]
mod tests {
    use crate::{overflow_lib::as_u16, overflow_lib::do_overflow};

    #[should_panic]
    #[test]
    fn int_overflow_simple() {
        let y_str = "2147483647";
        let y = y_str.parse::<i32>().unwrap();
        let x = do_overflow(y);
    }

    #[should_panic]
    #[test]
    fn int_overflow_in_cast() {
        let y_str = "2147483647";
        let y = y_str.parse::<i32>().unwrap();
        println!("{}", y);
        let a = as_u16(y);
    }
}
```

{{< /details >}}

Due to performance considerations, you are likely to want to enable the overflow checks only for testing and debug builds, not for release.

## Sanitizers

While Rust is memory-safe, one may open a gate to the unsafe world and introduce all the well-known vulnerabilities like use-after-free and reading of uninitialized memory. Moreover, the Rust compiler does not provide strong guarantees about [memory leaks](https://doc.rust-lang.org/book/ch15-06-reference-cycles.html) and [general race conditions](https://doc.rust-lang.org/nomicon/races.html).

To find deep bugs, we can run tests with [various sanitizers](https://doc.rust-lang.org/beta/unstable-book/compiler-flags/sanitizer.html). Sanitization in this context means that builds are instrumented during compilation and linked with specialized runtime libraries. Then, when executed, the instrumentation looks for a specific class of issues. Running tests with sanitizers comes with the downsides of increased compilation time, execution time, and memory usage.

Examples of Rust sanitizers commonly used for security testing include:

* AddressSanitizer
* HWAddressSanitizer
* LeakSanitizer
* MemorySanitizer
* ThreadSanitizer

To enable them, set the `RUSTFLAGS` environment variable.

The examples below run the subset supported by the shown `x86_64-unknown-linux-gnu` target. Sanitizers are target-specific, so adjust the sanitizer name and target triple for others like HWAddressSanitizer.

{{< hint warning >}}
At this time, nightly toolchains must be used for sanitizers. If you use the stable toolchain, the compilation fails with the following error:

`error: failed to run rustc to learn about target-specific information`
{{< /hint >}}

{{< tabs "rust-sanitizers" >}}
{{< tab "Cargo test" >}}

```sh
for sanitizer in "address" "leak" "memory" "thread"; do
    echo "Testing with $sanitizer"
    export RUSTFLAGS="-Z sanitizer=$sanitizer"
    export RUSTDOCFLAGS="$RUSTFLAGS"
    cargo +nightly test -Zbuild-std --target x86_64-unknown-linux-gnu
done
```

{{< /tab >}}
{{< tab "Cargo nextest" >}}

```sh
for sanitizer in "address" "leak" "memory" "thread"; do
    echo "Testing with $sanitizer"
    export RUSTFLAGS="-Z sanitizer=$sanitizer"
    export RUSTDOCFLAGS="$RUSTFLAGS"
    cargo +nightly nextest run -Zbuild-std --target x86_64-unknown-linux-gnu
done
```

{{< /tab >}}
{{< /tabs >}}

A few tips:

* If compilation fails, [add an explicit `--target` option](https://github.com/rust-lang/rust/issues/48199#issuecomment-743406233) and use the nightly toolchain.

* Use the `rustup toolchain list` command to find available toolchains.

* Not all targets are created equal. Check [which are supported by the given sanitizer](https://github.com/rust-lang/rust/issues/123615#issuecomment-2041791236).

* Use both `RUSTFLAGS` and `RUSTDOCFLAGS` if there are any doctests.

* Sanitizers are not compatible with each other. Compile with one sanitizer at a time. One exception is AddressSanitizer and LeakSanitizer that can work together.

* [It is required](https://doc.rust-lang.org/beta/unstable-book/compiler-flags/sanitizer.html#instrumentation-of-external-dependencies-and-std) to recompile the standard library with `-Zbuild-std` when using ThreadSanitizer and MemorySanitizer. It is recommended for AddressSanitizer.

* MemorySanitizer needs all the code to be sanitized. Any C/C++ dependencies must be built with the `-fsanitize=memory` flag (in addition to the standard library).

* Note the following for ThreadSanitizer:

  * A known limitation is lack of support for `std::sync::atomic::fence` and inline assembly code.

  * To reduce false positives, use a single thread for testing (`RUST_TEST_THREADS=1` or `--test-threads=1`). Note that ThreadSanitizer errors on multi-threaded test execution may indicate bugs in tests themselves (not in the actual code) and may be worth investigating.

{{< details "Example to try: testing with ASAN" >}}

The test below passes, but there is actually a bug. AddressSanitizer can help us find it.

```sh
RUSTFLAGS='-Z sanitizer=address' cargo +nightly test -Zbuild-std --target x86_64-unknown-linux-gnu
```

```rust
fn main() { println!("Hello, world!"); }

#[cfg(test)]
mod tests {
    #[test]
    fn uaf() {
        let a = vec![7, 3, 3, 1];
        let b = a.as_ptr();
        drop(a);
        let z = unsafe { *b };
    }
}
```

{{< /details >}}

## Miri

[Miri](https://github.com/rust-lang/miri) is an interpreter for Rust’s "mid-level intermediate representation." Miri helps detect undefined behavior and related issues like these:

* Memory corruption bugs
* Memory leaks
* Uses of uninitialized data
* Memory alignment issues
* Issues with aliasing
* Data races

To use Miri, you must point it at some executable code (it performs dynamic analysis). The easiest is to run your tests through Miri. Note that the nightly toolchain is required.

{{< tabs "miri-tests" >}}
{{< tab "Miri with cargo test" >}}

```sh
rustup +nightly component add miri
cargo +nightly miri test
```

{{< /tab >}}
{{< tab "Miri with nextest" >}}

```sh
cargo +nightly miri nextest run
```

{{< /tab >}}
{{< /tabs >}}

Alternatively, you can replace debug builds with Miri for use in testing environments. You need to replace the compiled binary with the invocation of a full Cargo command, as Miri does not compile instrumented binaries but rather is an interpreter.

```sh
cargo +nightly miri run
```

Lastly, you can combine fuzzing with Miri. The fuzzer should produce inputs that make the test harnesses cover a decent fraction of the code, probably more than unit tests. Miri can take advantage of the generated inputs:

1. [Fuzz your code as usual]({{% relref "/docs/fuzzing/rust" %}}).
2. For every file generated by the fuzzer, run the code under Miri.

Unfortunately, [there is no single command](https://github.com/rust-fuzz/cargo-fuzz/issues/370) to combine fuzzing with Miri. You need to add a test for every harness. To do that efficiently you can use test fixtures via [`rstest`](https://docs.rs/rstest/latest/rstest/) crate. For example, the code to fuzz the binary `fuzz_target_1` could look like this:

```rust
#![cfg_attr(not(any(miri, test)), no_main)]

use libfuzzer_sys::fuzz_target;
use rust_tests::check_buf;
fn harness(data: &[u8]) {
    check_buf(data);
}

fuzz_target!(|data: &[u8]| {
    harness(data);
});

#[cfg(test)]
#[cfg(miri)]
mod tests {
    use {
        crate::{harness},
        rstest::rstest,
        std::{fs::File, io::Read, path::PathBuf},
    };

    #[rstest]
    fn miri(#[files("corpus/fuzz_target_1/*")] path: PathBuf) {
        let mut input = File::open(path).unwrap();
        let mut buf = Vec::new();
        input.read_to_end(&mut buf).unwrap();
        harness(&buf);
    }
}
```

You'd then run this command. The Miri isolation must be disabled in order to access the corpus files.

```sh
MIRIFLAGS="-Zmiri-disable-isolation" cargo +nightly miri nextest run --bin fuzz_target_1
```

Keep these tips in mind while using Miri:

* Miri can be pretty slow.

  * Use it carefully in CI jobs.

  * Try to slice your tests into reasonably sized functions.

  * Disable the longest-running tests if needed.

  * Consider disabling the most heavy Miri detectors like `-Zmiri-disable-stacked-borrows` and `-Zmiri-disable-validation`.

  * Use [`--test-threads` or `-j` flag with `nextest`](https://nexte.st/docs/integrations/miri/#benefits) to improve the speed.

    * Data races on resources shared between testing threads [will not be detected](https://github.com/rust-lang/miri#:~:text=Note%3A%20This%20one%2Dtest%2Dper%2Dprocess%20model%20means).

* Note that doctests are [not supported yet](https://github.com/nextest-rs/nextest/issues/16) by `nextest`.

* For safe programs, Miri still can provide value.

  * Bugs may lie inside unsafe dependencies.

  * Memory leaks and some data races can be present even in safe Rust.

* Miri implements a very limited subset of operating system APIs.

  * It includes only basic support for stdout printing, filesystem access, and environment variables.

  * It has no FFI support.

  * You may need to split your tests into "impure" functions (those that call unimplemented APIs) and "pure" functions (those that do not), and run Miri only on the latter.

* Use `MIRIFLAGS="-Zmiri-disable-isolation"` and `RUSTFLAGS="-Zrandomize-layout"` to make runs less deterministic.

* Miri downloads and compiles Rust sysroot when compiling your code.

  * You must enable network access and [disable dependency vendoring](https://fuchsia.dev/fuchsia-src/development/languages/rust/miri#setup_miri) to use Miri.

* Some of Miri’s checks are not enabled by default.

  * For example, use `-Zmiri-tree-borrows` to replace experimental stacked borrows with (also experimental and newer) tree borrows.

* Keep an eye on [Ralf’s blog](https://www.ralfj.de/blog/), where new Miri features are summarized.

{{< details "Example to try: Miri in action" >}}

The test below may pass or fail normally, but Miri should report undefined behavior.

```rust
fn main() { println!("Hello, world!"); }

#[cfg(test)]
mod tests {
    fn x() {}


    #[test]
    fn miri_example() {
        let f = x as *const usize;
        let y = unsafe {
            *f.map_addr(|a| a + 8)
        };
        assert_eq!(y, 0x841f0f);
    }
}
```

{{< /details >}}

## Property testing with proptest

Normal unit tests are great for testing a single scenario. You test code by providing a single, specific value and checking if the code behaves as expected.

But instead of using a single value, you can generate a set of inputs and execute the unit test multiple times to check if it works correctly for every input. This is called "property testing," as you are effectively verifying that some property (the test case) holds for all (or many) expected inputs.

How do you know if you should use property testing over normal unit testing?

* Property testing: Complex code, tedious to enumerate examples, high correctness requirements, [high-leverage scenarios]({{% relref "/docs/fuzzing#what-to-fuzz" %}})
* Unit testing: Simple code, behavior best communicated by specific cases, regression tests

Let’s use the [proptest](https://github.com/proptest-rs/proptest) tool for the task. It is a tool inspired by the famous [QuickCheck](https://hackage.haskell.org/package/QuickCheck).

First, install the tool as a dev dependency:

```toml
[dev-dependencies]
proptest = "1.11.0"
# Only needed for the `#[derive(Arbitrary)]` example below
proptest-derive = "0.8.0"
```

To use proptest, you must write unit tests. But instead of hard-coding values that are used for testing, you define generators for values (called "strategies" in proptest’s docs). Proptest will execute the unit test dozens of times with randomly generated values.

Proptest ships with many [configurable strategies](https://docs.rs/proptest/latest/proptest/):

* Range-like generator for integers
* Regex generator for strings
* Simple generators for `bit`, `bool`, and `char` values
* Random-size generators for `std::collections`
* Generators for `Option` and `Result`

The generators [can be combined together](https://proptest-rs.github.io/proptest/proptest/tutorial/macro-prop-compose.html). You can also use the following `Strategy` methods and the `prop_oneof!` macro to further combine and restrict generation:

* Do mapping with the `prop_map` method
* Do filtering with the `prop_filter` method
* Create enums with the `prop_oneof!` macro
* Do recursion with the `prop_recursive` method

Let’s see some example code:

```rust
fn simple_thingy_dingy(a: u64, b: &str) -> u64 {
    return a + match b.parse::<u64>() {
        Ok(x) => x,
        Err(_) => b.len() as u64,
    };
}

#[cfg(test)]
mod tests {
    use crate::simple_thingy_dingy;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        #[test]
        fn test_simple_thingy_dingy(a in 1337..7331u64, b in "[0-9]{1,3}") {
            println!("{a} | {b}");
            let sum = simple_thingy_dingy(a, &b);
            assert!(sum >= a);
            assert!(sum > 1337);
        }
    }
}
```

The `simple_thingy_dingy` function is a function we want to unit-test. To do so, we need to wrap the test for it with the `proptest!` helper. Then, we use two generators for values `a` and `b`: a range-like generator for integers and a regex generator for strings.

Now, we just need to run `cargo test` and wait for the proptest to finish. Running `cargo test -- --show-output` will enable us to observe what values were generated.

By default, proptest executes a unit test 256 times, but we can change that with `ProptestConfig::with_cases`.

If the test finds an input failing the unit test, it writes the input to the `proptest-regressions` directory.

As can be seen, we have to write a strategy for every single value we use. However, we could instead create [a strategy for a type](https://proptest-rs.github.io/proptest/proptest/tutorial/arbitrary.html) using the `Arbitrary` trait, which the `proptest-derive` crate can derive for us.

```rust
#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use proptest_derive::Arbitrary;

    #[derive(Debug, Arbitrary)]
    struct Point {
        #[proptest(strategy = "-100i32..=100")]
        x: i32,
        #[proptest(strategy = "-100i32..=100")]
        y: i32,
    }

    impl Point {
        fn distance_from_origin(&self) -> f64 {
            ((self.x.pow(2) + self.y.pow(2)) as f64).sqrt()
        }
    }

    proptest! {
        #[test]
        fn test_distance_is_non_negative(point: Point) {
            prop_assert!(point.distance_from_origin() >= 0.0);
        }

        #[test]
        fn test_distance_within_bounds(point: Point) {
            // Max distance: sqrt(100^2 + 100^2) ≈ 141.4
            prop_assert!(point.distance_from_origin() <= 150.0);
        }
    }
}
```

{{< hint info >}}
You can combine proptest with other improvements like sanitizers and Miri to enhance your testing even further.

To use proptest with Miri, you have to disable persistence (the `proptest-regressions` directory):

```sh
PROPTEST_DISABLE_FAILURE_PERSISTENCE=true \
MIRIFLAGS='-Zmiri-env-forward=PROPTEST_DISABLE_FAILURE_PERSISTENCE' \
cargo +nightly miri test
```

{{< /hint >}}

Finally, use our [`property-based-testing`](https://github.com/trailofbits/skills/tree/main/plugins/property-based-testing) skill to automate the testing.

## Coverage

It is critically important to know how much coverage your tests have. Coverage gathering consists of four steps:

* Compile-time instrumentation
* Execution of tests, producing "raw" data
* Merge of per-execution run results
* Conversion of merged data to a usable format (like an HTML report)

There are two main data formats:

* LLVM-style: `profraw` (per-process) and `profdata` (merged)
* gcov-style: `gcno` (produced during compilation) and `gcda` (produced during execution)

The two pipelines line up roughly like this:

| Stage | LLVM | gcov |
| :---- | :---- | :---- |
| Compile-time mapping | `__llvm_covmap` section in binary | `.gcno` |
| Per-run raw output | `.profraw` (one per process) | `.gcda` (merged in place at process exit) |
| Offline merge tool | `llvm-profdata merge` → `.profdata` | `gcov-tool merge` (still `.gcda`) or `lcov --add-tracefile` (→ `.info`) |
| Report consumer | `llvm-cov` reads `.profdata` + binary | `gcov` / `lcov` / `genhtml` read `.gcno`+`.gcda` or `.info` |

There are four common instrumentation backends (engines):

* [LLVM Instrument Coverage](https://doc.rust-lang.org/rustc/instrument-coverage.html)
  * Compiler front-end inserts per-source-region counters, so the instrumentation knows about source-level constructs.
  * Counters are incremented in-process during execution and dumped at process exit by the `__llvm_profile_*` runtime.
* [LLVM SanitizerCoverage](https://clang.llvm.org/docs/SanitizerCoverage.html)
  * Compiler inserts low-overhead `__sanitizer_cov_*` callbacks at functions, basic blocks, edges, or comparisons.
  * Callbacks fire at runtime and are consumed in-process by fuzzers for corpus guidance.
* [GCC `gcov`](https://gcc.gnu.org/onlinedocs/gcc/Gcov.html)
  * Compiler back-end pass instruments CFG arcs (basic-block edges), with no source-level awareness beyond debug info.
  * Counters are incremented in-process during execution and flushed at process exit by the gcov runtime.
* ptrace-based
  * No compile-time instrumentation; a tracer places `INT3` breakpoints on each statement's first instruction.
  * The tracer counts hits at runtime by handling `SIGTRAP` via `ptrace`.

{{< hint danger >}}
The `gcov` engine is [no longer supported by Rust](https://github.com/rust-lang/rust/pull/131829).
The engine and gcov-style format are still often used for C/C++ codebases.
{{< /hint >}}

{{< hint warning >}}
SanitizerCoverage is not meant for general coverage analysis, [but for fuzzing]({{% relref "/docs/fuzzing/rust/techniques/01-coverage" %}}).
{{< /hint >}}

Three popular tools wrap the above engines for easier consumption in Rust projects: [`grcov`](https://github.com/mozilla/grcov), [`llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov), and [`tarpaulin`](https://github.com/xd009642/tarpaulin).

| Feature/tool | `grcov` | `llvm-cov` | `tarpaulin` |
| :---- | :---- | :---- | :---- |
| Backends | LLVM | LLVM | LLVM, ptrace |
| Consumes | `profraw`/`profdata` or `gcno`/`gcda` | `profraw`/`profdata` | its own raw output |
| Coverage | Lines, functions, branches | Lines, functions, branches, regions, MC/DC | Lines |
| Output format | LCOV, JSON, HTML, Cobertura, Coveralls+, Markdown, ADE | Text, LCOV, JSON, HTML, Cobertura, Codecov | Text, LCOV, JSON, HTML, XML |
| To exclude files | `--ignore` | [`--ignore-filename-regex`](https://github.com/taiki-e/cargo-llvm-cov?tab=readme-ov-file#exclude-file-from-coverage) | `--exclude-files` |
| To exclude functions | With in-code markers and regexes | [With attributes](https://github.com/taiki-e/cargo-llvm-cov?tab=readme-ov-file#exclude-function-from-coverage) | [With attributes](https://github.com/xd009642/tarpaulin?tab=readme-ov-file#ignoring-code-in-files) |
| To exclude test coverage | No | [With external module](https://github.com/taiki-e/coverage-helper/tree/v0.2.0) | `--ignore-tests` |
| To enable coverage for C/C++ | Unknown | [`--include-ffi`](https://github.com/taiki-e/cargo-llvm-cov?tab=readme-ov-file#get-coverage-of-cc-code-linked-to-rust-librarybinary) | Unknown |
| Merges runs across different builds? | No | [Yes](https://github.com/taiki-e/cargo-llvm-cov?tab=readme-ov-file#merge-coverages-generated-under-different-test-conditions) | [Yes](https://github.com/xd009642/tarpaulin?tab=readme-ov-file#command-line) (but only shows delta) |

{{< hint warning >}}
Branch coverage from the LLVM source-based engine—the `branches` cells for `grcov` and `llvm-cov` above—requires a **nightly** toolchain compiled with [`-Zcoverage-options=branch`](https://doc.rust-lang.org/rustc/instrument-coverage.html#-zcoverage-options). On a stable toolchain, `grcov`'s `--branch` flag is silently ignored and no branch data is produced, which is why the example reports below show zero branches.
{{< /hint >}}

While checking coverage statistics from a command line and using one of many coverage visualizers, an HTML report is often what you need.

| HTML output/tool | `grcov` | `llvm-cov` | `tarpaulin` |
| :---- | :---- | :---- | :---- |
| Examples | [Open `grcov`]({{% staticref "/languages/rust/coverage/grcov_llvm/" %}}) [Open `grcov` with `lcov`]({{% staticref "/languages/rust/coverage/grcov_llvm_lcov/" %}}) | [Open `llvm-cov`]({{% staticref "/languages/rust/coverage/llvm_cov/" %}}) [Open `llvm-cov-pretty`]({{% staticref "/languages/rust/coverage/llvm_cov_pretty/" %}}) | [Open `tarpaulin`]({{% staticref "/languages/rust/coverage/tarpaulin-report.html" %}}) |
| Handles Rust constructs? | Yes | Yes | Yes |
| Expands Rust’s generics? | No | `--show-instantiations` | No |
| Includes number of hits? | Yes | Yes | Yes |
| Supports multi-file output? | Yes | Yes | No |

{{< tabs "coverage-html-reports" >}}
{{< tab "grcov llvm" >}}
![grcov HTML report](grcov_llvm1.png)

---

![grcov HTML report 2](grcov_llvm2.png)
{{< /tab >}}

{{< tab "grcov llvm with lcov" >}}
![grcov + lcov HTML report](grcov_llvm_lcov1.png)

---

![grcov + lcov HTML report 2](grcov_llvm_lcov2.png)
{{< /tab >}}

{{< tab "llvm-cov" >}}
![llvm-cov HTML report](llvm_cov1.png)

---

![llvm-cov HTML report 2](llvm_cov2.png)
{{< /tab >}}

{{< tab "llvm-cov with llvm-cov-pretty" >}}
![llvm-cov-pretty HTML report](llvm_cov_pretty1.png)

---

![llvm-cov-pretty HTML report 2](llvm_cov_pretty2.png)
{{< /tab >}}

{{< tab "tarpaulin" >}}
![tarpaulin HTML report](tarpaulin1.png)

---

![tarpaulin HTML report 2](tarpaulin2.png)
{{< /tab >}}

{{< /tabs >}}

These are our general recommendations for generating test coverage:

* Use `llvm-cov` (with [`llvm-cov-pretty`](https://crates.io/crates/llvm-cov-pretty)) for rapid testing. It is the easiest to run, it resolves generics, and it produces pretty HTML output.
* Use either `llvm-cov` or `grcov` for complex projects. Both are decent and can produce readable outputs.
* Use `tarpaulin` when other tools work incorrectly. [The developers claim](https://github.com/xd009642/tarpaulin?tab=readme-ov-file#nuances-with-llvm-coverage) that this can happen in the event of the following:
  * The code panics unexpectedly.
  * There are race conditions.
  * The code forks.

For profiling, consider using [`measureme`](https://github.com/rust-lang/measureme), possibly with [Miri and Chrome DevTools](https://medium.com/source-and-buggy/data-driven-performance-optimization-with-rust-and-miri-70cb6dde0d35).

{{< hint info >}}
Go to the [Testing Handbook repository’s `materials/rust/coverage`](https://github.com/trailofbits/testing-handbook/tree/main/materials/rust/coverage) folder.
There you will find a Dockerfile that generated HTML reports shown above.
{{< /hint >}}

## Validation of tests (mutation testing)

Who tests the tests? What if tests miss an important branch? What if your critical test has a bug that makes it pass incorrectly? We recommend using mutation testing to validate your tests.

### Gaps in test coverage

Mutation testing involves modifying the source code and then running the tests to see if they catch those modifications (called mutants). You can read more about this testing technique in our blog post ["Use mutation testing to find the bugs your tests don't catch"](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/).

For starters, you need basic but decent unit test coverage. Then, use one of the following tools to automatically get a list of code areas that are not sufficiently tested or may be buggy.

[`cargo-mutants`](https://mutants.rs/welcome.html)

* Easy to use
* Parses the AST of every file with the [`syn` library](https://docs.rs/syn/latest/syn/)
* Partially type-aware
* Can [divide jobs](https://mutants.rs/shards.html) between multiple machines

[`universalmutator`](https://github.com/agroce/universalmutator)

* Multiple languages supported
* Requires more manual setup than `cargo-mutants`
* Two parsing modes: regexes and [Comby](https://github.com/comby-tools/comby)
* Trivial Compiler Equivalence (TCE) optimization to eliminate redundant mutants before test runs

### Bugs in existing tests

A unique approach to finding bugs in tests is to mutate them and check if they pass. If they do, it indicates that something may be wrong with them. This is different from mutating the actual code: we aim to find bugs in the tests, not coverage gaps or bugs in the code.

To automate the process of mutation and validation, [use Necessist](https://github.com/trailofbits/necessist).

```sh
cargo install necessist
```

Necessist works by iterating over the statements in each test, removing them one at a time, and checking whether the test still passes. A mutated test that passes with an instruction removed is shown as the following:

```text
filename:line-line `removed code` passed
```

If a test still passes after an instruction was removed, then that instruction is redundant and does not change the test’s behavior, indicating there may be a bug in the test. A manual investigation is then needed to determine if there really is a bug.

{{< hint info >}}
While Necessist aims to find bugs in the tests, its findings can sometimes reveal issues in the actual code.
{{< /hint >}}

{{< details "Example to try: testing with Necessist" >}}

Necessist should report that the `parser_detects_errors` test passes even if one line is removed from it. This indicates that the magic number in either the test or the `validate_data` function is incorrect, preventing the "real" bug from being tested properly.

```rust
fn validate_data(data: &Data) -> Result<(), ()> {
    if !data.magic.eq(&[0x13, 0x37]) { return Err(()) }
    if data.len as usize != data.content.len() { return Err(()) }
    return Ok(());
}

struct Data {
    magic: [u8; 2],
    len: u8,
    content: String
}

#[cfg(test)]
mod tests {
    use crate::{Data, validate_data};

    #[test]
    fn parser_detects_errors() {
        let mut blob = Data{
            magic: [0x73, 0x31],
            len: 2,
            content: "AB".parse().unwrap(),
        };
        blob.content = blob.content + "Y";
        let result = validate_data(&blob);
        assert!(result.is_err());
    }
}
```

{{< /details >}}

Necessist is slow and sometimes produces a nontrivial number of false positives. We recommend running it manually from time to time instead of in a CI pipeline.

The tool produces a `necessist.db` file that can be used to resume an interrupted run. The database should be retained between runs to accelerate new tests.

## Resources

* ["The Rust Programming Language," chapter 11: Testing](https://web.mit.edu/rust-lang_v1.25/arch/amd64_ubuntu1404/share/doc/rust/html/book/second-edition/ch11-00-testing.html): The basics of unit and integration testing in Rust
* [Ed Page’s "Iterating on Testing in Rust"](https://epage.github.io/blog/2023/06/iterating-on-test/): Lists potential issues with `cargo` `test` and introduces `cargo-nextest`
* [Unsafe Rust and Miri by Ralf Jung \- Rust Zürisee June 2023](https://www.youtube.com/watch?v=svR0p6fSUYY)
