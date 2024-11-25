---
title: "Unit testing"
slug: rust-unit-testing
summary: "This section describes tricks for Rust unit testing"
weight: 1
---


# Unit testing

This is the most basic type of testing that every project should have.
Unit tests are easy to execute, low-effort to implement, and catch a lot of simple mistakes.

## Installation and first steps

The standard and ultimate tool for executing unit and integration tests for Rust codebases is `cargo test`.
The basic setup and usage of `cargo test` is well-known, so we will skip the introduction.

You can also try [the `cargo-nextest`](https://nexte.st/index.html) - a new test runner.


```rust
#[cfg(test)]
mod tests {
    #[test]
    fn true_dilemma() {
        assert_ne!(true, false);
    }
}
```


Please note that [`docs tests` don't work in binary targets](https://github.com/rust-lang/rust/issues/50784).

Once you have your tests written and all of them passes, lets improve.

## Improvements

### Randomization

First let's make sure that tests do not depend on a global state and that there are no unwanted dependencies between them.

For that you can run tests multiple times, taking advantage of the enabled-by-default parallel execution. However, this approach is not optimal. That is because tests are executed in basically alphabetical order, even when multi-threaded.

Better to run tests in a random order without parallel execution.

```sh
cargo test -- -Z unstable-options --test-threads 1 --shuffle 
```

Execute command above multiple times. If any run reports a failed test, use the displayed "shuffle seed" to reliably repeat the error:

```sh
cargo test -- -Z unstable-options --test-threads 1 --shuffle-seed 7331
```

{{< details "Example to try" >}}

Tests below fail randomly when run with `cargo test`. To get reproducible failure run:

```sh
cargo test -- -Z unstable-options --test-threads 1 --shuffle-seed 1337
```

```rust
fn main() { println!("Hello, world!"); }

static mut glob_var: i32 = 2;

unsafe fn global_var_set(arg: i32) {
    glob_var = arg;
}

#[cfg(test)]
mod tests {
    use crate::{glob_var, global_var_set};

    #[test]
    fn a_true_dilemma() {
        unsafe { assert_eq!(glob_var, 2); }
        unsafe { global_var_set(5); }
        unsafe { assert_eq!(glob_var, 5); }
        assert_ne!(true, false);
    }

    #[test]
    fn not_true_dilemma() {
        unsafe { assert_eq!(glob_var, 2); }
        assert_ne!(true, false);
    }
}
```

{{< /details >}}

When you are happy with the results, randomize features using [`cargo hack`](https://github.com/taiki-e/cargo-hack). Start with testing your code against all the features taken separately, then combine multiple features in one run:

```sh
cargo +stable install cargo-hack --locked
cargo hack test -Z avoid-dev-deps --each-feature
cargo hack test -Z avoid-dev-deps --feature-powerset --depth 2
```

{{< details "Example to try" >}}

The test below passes when run with `cargo test`. Also passes with `cargo hack test --each-feature`. To find the code path that makes the test fail run:

```sh
cargo hack test --feature-powerset --depth 2
```

```rust
fn main() { println!("Hello, world!"); }

fn feauture_one() -> i32 {
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
    use crate::{feauture_one};

    #[test]
    fn feature_test1() {
        let z = feauture_one();
        assert!(z < 3);
    }
}
```

{{< /details >}}

### Integer overflows

While some integer overflows are detected with [the `overflow-checks` flag](https://doc.rust-lang.org/rustc/codegen-options/index.html#overflow-checks), overflows in explicit casts are not. To make our tests detect overflows in `expr as T` expressions we must use [`cast_checks`](https://github.com/trailofbits/cast_checks).

Add relevant dependency to `Cargo.toml`:

```toml
[dependencies]
cast_checks = "0.1.4"
```

Now mark functions where you expect overflows with `#[cast_checks::enable]` and run tests as always.

Alternatively, enable `inner atributes` feature with `#![feature(custom_inner_attributes, proc_macro_hygiene)]` and put `#![cast_checks::enable]` attribute in relevant modules. When doing so add `RUSTFLAGS='--cfg procmacro2_semver_exempt'` to cargo commands.

{{< details "Example to try" >}}

The `int_overflow_simple` test always passes, as arithmetic overflows are detected with standard `overflow-checks`. However, to detect overflow in the `int_overflow_in_cast` we must use `cast_checks`.

```rust
#![feature(custom_inner_attributes, proc_macro_hygiene)]

fn main() { println!("Hello, world!"); }

mod lib {
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
    use crate::{lib::as_u16, lib::do_overflow};

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

### Sanitizers

While Rust is memory-safe, one may open a gate to the `unsafe` world and introduce all the well known vulnerabilities like use-after-free or reading of uninitialized memory. Moreover, Rust compiler does not prevent memory leaks and data races.

To find deep bugs we can enhance our tests with [various sanitizers](https://doc.rust-lang.org/beta/unstable-book/compiler-flags/sanitizer.html):

* AddressSanitizer
* LeakSanitizer
* MemorySanitizer
* ThreadSanitizer

To enable them:

```sh
RUSTFLAGS='-Z sanitizer=address' cargo test
RUSTFLAGS='-Z sanitizer=leak' cargo test --target x86_64-unknown-linux-gnu
RUSTFLAGS='-Z sanitizer=memory' cargo test --target aarch64-unknown-linux-gnu
RUSTFLAGS='-Z sanitizer=thread' cargo test
```

Not all targets are created equal, so check which are supported by the given sanitizer.

{{< details "Example to try" >}}

The test below passes. But the AddressSanitizer can help us find the bug.

```sh
RUSTFLAGS='-Z sanitizer=address' cargo test
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

### Miri

[Miri](https://github.com/rust-lang/miri) is an interpreter for Rust "mid-level intermediate representation ". You can run your tests through Miri with:

```
rustup +nightly component add miri
cargo miri test
```

Miri helps to detect:
* undefined behavior
* memory corruption bugs
* memory leaks
* uses of uninitialized data
* memory alignment issues
* issues with aliasing for reference types
* data races

## Property testing with Proptest

Normal unit tests are great for testing a single scenario - you test code by providing a single, specific
value and checking if the code behaves as expected.

But instead of using a single value, you can generate a set of inputs and execute the unit test multiple times
to check if it works correctly for every input.

Lets use [Proptest](https://github.com/proptest-rs/proptest) tool for that task. It is a tool inspired by the famous [QuickCheck](https://hackage.haskell.org/package/QuickCheck).

### Installation

Simply add the dev dependency to your project. Nothing more needed.

```toml
[dev-dependencies]
proptest = "1.0.0"
```

### Usage

To use Proptest you must write unit tests. But instead of hard-coding values that are used for testing,
you define *generators* for values (called "strategies" in proptest's docs).
Proptest will execute the unit test dozen of times with randomly generated values. 

Proptest ships with a dozen of [configurable strategies](https://docs.rs/proptest/latest/proptest/):
* range-like generator for `integers`
* regex generator for `strings`
* simple generators for `bits`, `bools`, `chars`
* random-size generators for `std:collections`
* generators for `Option` and `Result`

The generators [can be combined together](https://proptest-rs.github.io/proptest/proptest/tutorial/macro-prop-compose.html). You can also use macros to do further combine and restric generation:
* do mapping with `prop_map`
* do filtering with `prop_filter`
* create enums with `prop_oneof`
* do recursion with `prop_recursive`

Lets see an example code:

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

The `simple_thingy_dingy` is function we want to unit-test. For that we need to wrap a normal `#[test]` with `proptest!` helper.
Then we use two generators for `a` and `b` values: range-like for integers and regex for strings.

Now we just need to run `cargo test` and wait for the Proptest to finish. Running `cargo test -- --show-output`
will enable us to observe what values were generated.

By default Proptest executes an unit test 256 times, but we can change that with `ProptestConfig::with_cases`.

If the Proptest finds an input failing the unit test, it writes the input to the `proptest-regressions` directory.

As can be seen, we have to write a strategy for every single value we use. However, we could instead create [a strategy for a type](https://proptest-rs.github.io/proptest/proptest/tutorial/arbitrary.html) using the `Arbitrary` trait.

{{< hint info >}}
**You can combine Proptest with other improvements**  

Using Proptest with improvements [listed above](/docs/languages/rust/unit-tests/#improvements)
can enhance your testing even further.

To use with Proptest with Miri you have to disable persistence (the `proptest-regressions` directory):

```sh
PROPTEST_DISABLE_FAILURE_PERSISTENCE=true \
MIRIFLAGS='-Zmiri-env-forward=PROPTEST_DISABLE_FAILURE_PERSISTENCE' \
cargo miri test
```
{{< /hint >}}


## Coverage

It is critically important to know how much coverage your tests have. Coverage gathering consists of three steps:

* compile-time instrumentation
* execution of tests, producing "raw" data
* convertion of "raw" data to an usable format

There are three common instrumentation backends (engines):

* GCC's `gcov`
    * produces `gcno` (during compilation) and `gcda` (during execution) raw data
* LLVM's `SanitizerCoverage`
    * produces `profraw` raw data
    * can produce `gcno`&`gcda` raw data - not supported in the tooling below 
* `ptrace`-based
    * produces `profraw` raw data

There are three popular tools wrapping the above engines for easier consumption in Rust projects.
Instead of them you can directly use [the tools described in the fuzzing chapter](#) (TODO: link).

| Feature \ Tool | [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov)  | [`cargo-tarpaulin`](https://github.com/xd009642/tarpaulin) | [`grcov`](https://github.com/mozilla/grcov)
| ----------- | ----------- | ----------- | ----------- |
| Backends                | LLVM                                        | LLVM, ptrace |  LLVM, gcov |
| Coverage                | Lines, functions, regions                   | Lines        |  Lines, functions, branches |
| Output format           | Text, lcov, JSON, HTML, cobertura, codecov  | Text, lcov, JSON, HTML, xml        |  Lcov, JSON, HTML, cobertura, coveralls+, markdown, ade |
| Exclude files           | [`--ignore-filename-regex`](https://github.com/taiki-e/cargo-llvm-cov?tab=readme-ov-file#exclude-file-from-coverage)   | `--exclude-files`        |  `--ignore` |
| Exclude functions       | [With attributes](https://github.com/taiki-e/cargo-llvm-cov?tab=readme-ov-file#exclude-function-from-coverage)   | [With attributes](https://github.com/xd009642/tarpaulin?tab=readme-ov-file#ignoring-code-in-files)        |  With in-code markers & regexes |
| Exclude tests' coverage | [With external module](https://github.com/taiki-e/coverage-helper/tree/v0.2.0)   | `--ignore-tests`        |  No |
| Coverage for C/C++      | [`--include-ffi`](https://github.com/taiki-e/cargo-llvm-cov?tab=readme-ov-file#get-coverage-of-cc-code-linked-to-rust-librarybinary)   | `--follow-exec`        |  ? |
| Merge data from multiple runs | [Yes](https://github.com/taiki-e/cargo-llvm-cov?tab=readme-ov-file#merge-coverages-generated-under-different-test-conditions)  | [Yes/No](https://github.com/xd009642/tarpaulin?tab=readme-ov-file#command-line) (only shows delta)            |  No |

While checking coverage statistics from a command line and using one of many coverage-visualizers,
HTML report is often what you need.

| HTML output \ Tool | `cargo-llvm-cov` | `cargo-tarpaulin` | `grcov` |
| ----------- | ----------- | ----------- | ----------- |
| Examples    | [Open `llvm-cov`](/samples_rust_coverage/llvm_cov/index.html?:), [open `llvm-cov-pretty`](/samples_rust_coverage/llvm_cov_pretty/index.html?:) | [Open `tarpaulin`](/samples_rust_coverage/tarpaulin-report.html?:) | [Open `grcov`](/samples_rust_coverage/grcov/index.html?:), [open `grcov` with `lcov`](/samples_rust_coverage/grcov_lcov/index.html?:) |
| Handles Rust's constructions | Yes | Yes | Yes |
| Expands Rust's generics | `--show-instantiations` | No | No |
| Number of hits | Yes | No | Yes |
| Multi-file output | Yes | No | Yes |

For post-processing (generating HTML reports, like merging files from multiple runs, and excluding selected files, ..)
of `lcov` outputs you can use:
* [The `lcov` tool's  `genhtml` utility](https://github.com/linux-test-project/lcov)
* [`llvm-cov-pretty`](https://github.com/dnaka91/llvm-cov-pretty)

Our recommendations are:
* Use `cargo-llvm-cov` (with `llvm-cov-pretty`) for rapid testing: easiest to run, can resolve generics
* Use either `cargo-llvm-cov` or `grcov` for complex projects: both are decent, unique, and produce multi-file HTML output
* Use `cargo-tarpaulin` when other tools works incorrectly. [Authors claim](https://github.com/xd009642/tarpaulin?tab=readme-ov-file#nuances-with-llvm-coverage) that these can happen when:
    * the code panic unexpecteadly
    * there are race conditions
    * the code forks

{{< details title="Example to try" open=true >}}
Go to the [Testing Handbook's repository `samples/rust_coverage`](https://github.com/trailofbits/testing-handbook/tree/main/samples/rust_coverage/) folder.

There you will find Dockerfile generating HTML reports using the described tools.
{{< /details >}}


## Validation of tests

Who tests tests? What if your critical test has a bug that makes it to pass incorrectly?

To find issues in your tests [use `necessist`](https://github.com/trailofbits/necessist).

```sh
cargo install necessist
necessist
```

Necessist works by mutating tests - removing certain instructions from them - and executing them.
A mutated test that passed with an instruction removed is shown as:

```
filename:line-line `removed code` passed
```

It requires manual investigation if a finding really revealed a bug in a testcase (or in the code being tested).

The tool produces a `necessist.db` file that can be used to resume an interrupted run.

{{< details "Example to try" >}}

Necessist should report that the `parser_detects_errors` test passes even if one line is removed from it.
It indicates that either magic number in the example or in the `validate_data` is incorrect, preventing the "real"
bug from being tested properly.

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

Necessist is slow and sometimes produces false positives. We recommend running it manually from time to time, instead of in a CI pipeline. The database should be kept between runs to accellerate new tests. Please report any false-positives on GitHub.

## Resources

* ["The Rust Programming Language", chapter 11. Testing](https://web.mit.edu/rust-lang_v1.25/arch/amd64_ubuntu1404/share/doc/rust/html/book/second-edition/ch11-00-testing.html): the basics of unit and integration testing in Rust
* [Ed Page's "Iterating on Testing in Rust"](https://epage.github.io/blog/2023/06/iterating-on-test/): lists potential issues with `cargo test` and introduces `cargo-nextest`
