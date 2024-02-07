---
title: "Writing harnesses"
slug: writing-harnesses
summary: "TODO"
weight: 2
---




##### Writing harnesses {#writing-harnesses}

In the following, we will go over Rust specific tips to optimize the results from your harnesses. For general advice, refer to [Writing harnesses](#writing-harnesses).

###### Structure-Aware Fuzzing with the arbitrary crate {#structure-aware-fuzzing-with-the-arbitrary-crate}

The [arbitrary](https://github.com/rust-fuzz/arbitrary) crate simplifies writing fuzzing harnesses. By deriving a macro, Rust structs can be targeted for fuzzing. For example, the following code requires constructing a `Name` struct that owns a `String`. We derived the Arbitrary macro to facilitate the construction of such a `Name`.

{{< customFigure "Rust code in the crate `your_project` that uses the arbitrary crate" >}}
```Rust
use arbitrary::{Arbitrary};

#[derive(Debug, Arbitrary)]
pub struct Name {
    data: String
}

impl Name {
    pub fn check_buf(&self) {
        let data = self.data.as_bytes();
        if data.len() > 0 && data[0] == b'a' {
            if data.len() > 1 && data[1] == b'b' {
                if data.len() > 2 && data[2] == b'c' {
                    process::abort();
                }
            }
        }
    }
}
```
{{< /customFigure >}}

With the arbitrary crate, we can easily write a fuzzing harness for this test, similar to the harness in [Write a Fuzz test](#write-a-fuzz-test).


{{< customFigure "Fuzz test using the arbitrary crate" >}}
```Rust
#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

fn harness(data: &[u8]) {
    // Wrap it in an `Unstructured`.
    let mut unstructured = Unstructured::new(data);

    // Generate an `Name` and run our checks.
    if let Ok(name) = your_project::Name::arbitrary(&mut unstructured) {
        name.check_buf();
    }
}

fuzz_target!(|data: &[u8]| {
    harness(data);
});
```
{{< /customFigure >}}

The cargo-fuzz tool actually supports the arbitrary crate, so we can simplify this.

{{< customFigure "Shortened fuzz test using the arbitrary crate" >}}
```Rust
#![no_main]

use libfuzzer_sys::fuzz_target;

fn harness(data: &your_project::Name) {
    data.check_buf();
}

fuzz_target!(|data: your_project::Name| {
    harness(&data);
});
```
{{< /customFigure >}}

Both of the above examples require the arbitrary crate to be a dependency of your library crate. In the first example, you also need to add the dependency to the `Cargo.toml` in the `fuzz/` directory. The second example does not require this because the arbitrary dependency of the `libfuzzer_sys` dependency is used. Here is the dependency declaration you need:




{{< customFigure "Dependency declaration for the arbitrary crate" >}}
```toml
[dependencies]
arbitrary = { version = "1", features = ["derive"] }
```
{{< /customFigure >}}

As usual, the fuzz test can be started using the following command:


```shell
cargo +nightly fuzz run fuzz_target_1 
```


The arbitrary crate essentially offers a way to deserialize byte arrays to Rust structs. However, it is limited in that it does not offer the reverse function: serializing Rust structs to byte arrays. This becomes a problem when trying to prepare a corpus of seeds. It is not possible to purposefully construct byte-arrays that construct a specific Rust struct.

Therefore, the arbitrary crate is useful only when starting from an empty corpus. This is not an issue when using cargo-fuzz because it uses libFuzzer internally, and libFuzzer supports starting from an empty corpus. However, other fuzzers like AFL++ require a seed input.


