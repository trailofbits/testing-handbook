---
title: "Unit tests"
slug: unit-tests
summary: "This section describes tricks for Rust unit testing"
weight: 1
---

# Unit tests

This is the most basic type of testing that every project should have. Unit tests are easy to execute, low-effort to implement, and catch a lot of simple mistakes.


## Installation and first steps

The standard and ultimate tool for executing unit and integration tests for Rust codebases is the `cargo test`. The basic setup and usage of `cargo test` is well-known, so we will skip the introduction.

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


## Advanced usage

### Randomization

First lets make sure that tests do not depend on a global state and that there are no unwanted dependencies between them.

For that you can run tests multiple times, taking adventage of the enabled-by-default parallel execution. However, this approach is not optimal. That is because tests are executed in basically alphabetical order, even when multi-threaded.

Better to run tests in a random order without parallel execution.
```sh
cargo test -- -Z unstable-options --test-threads 1 --shuffle 
```

Execute command above multiple times. If any run reported a failed test use the displayed "shuffle seed" to reliably repeat the error: 
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


### Coverage

It is critically important to know how much coverage your tests have. To gather coverage information use one of:

| Feature | [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov)  | [`cargo-tarpaulin`](https://github.com/xd009642/tarpaulin) | [`grcov`](https://github.com/mozilla/grcov)
| -----------| ----------- | ----------- | ----------- |
| Backends   | LLVM      | LLVM, ptrace       |  ? |
| Output format  | console, html   | html        |  ? |
| Coverage  | console, html   | html        |  ? |
| Merge  | console, html   | html        |  ? |
| Exclude files  | console, html   | html        |  ? |
| Exclude functions  | console, html   | html        |  ? |
| Exclude tests' coverage  | console, html   | html        |  ? |
| Coverage for C/C++  | console, html   | html        |  ? |

* 
```
cargo llvm-cov # console
cargo llvm-cov --open # html

backend: llvm

# coverage: function, lines, region; no branch cov

# merge
cargo llvm-cov clean --workspace # remove artifacts that may affect the coverage results
cargo llvm-cov --no-report --features a
cargo llvm-cov --no-report --features b
cargo llvm-cov report --lcov # generate report without tests

# show change in coverge - no

# support for C/C++ code - yes
# exclude file - --ignore-filename-regex
# exclude function - (unstable) #[cfg_attr(coverage_nightly, coverage(off))]
# exclude test code - https://github.com/taiki-e/coverage-helper/tree/v0.2.0
```

* 
```
cargo tarpaulin # console
cargo tarpaulin --out html # html

backend: llvm, ptrace

# cove: lines; no branch, function, regions cov

--no-fail-fast
 --ignore-panics should_panic

# show change in coverge - yes

# support for C/C++ code - --follow-exec ?
# exclude file - #[cfg(not(tarpaulin_include))]
# exclude test code - #[cfg_attr(tarpaulin, ignore)]
# exclude test code - --ignore-tests
```

* 
```
html - yes
console - no

# cove: lines, function, branches
```


### Validation of tests

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

## CI/CD integration

Describe how to setup and use `<tool>` in CI/CD

## Resources

* ["The Rust Programming Language", chapter 11. Testing](https://web.mit.edu/rust-lang_v1.25/arch/amd64_ubuntu1404/share/doc/rust/html/book/second-edition/ch11-00-testing.html) - the basics of unit and integration testing in Rust
* [Ed Page's "Iterating on Testing in Rust"](https://epage.github.io/blog/2023/06/iterating-on-test/) - potential issues with `cargo test`
