---
title: "cargo-fuzz"
slug: cargo-fuzz
weight: 2
---



# cargo-fuzz {#cargo-fuzz}

The cargo-fuzz tool is the de facto choice for fuzzing your Rust project when using Cargo. It uses libFuzzer as the back end. Note that if you are not using Cargo, you cannot use the cargo-fuzz tool.

By installing the cargo-fuzz crate, a Cargo subcommand is installed. Therefore, cargo-fuzz depends on using Cargo. The subcommand also automatically enables relevant compilation flags for your Rust project and even supports enabling sanitizers like AddressSanitizer.


## Installation {#installation}

The cargo-fuzz tool uses features that are available only in the nightly Rust toolchain. You can install it using [rustup](https://rustup.rs/).


```shell
rustup install nightly
```


Verify that the installation was successful by running the following command.


```shell
cargo +nightly --version
```


The recommended way of installing the tool itself is through `cargo install`.


```shell
cargo install cargo-fuzz
```

## Write a fuzz test {#write-a-fuzz-test}

Let's recall the example introduced in the [introduction]({{% relref "fuzzing#introduction-to-fuzzers" %}}) of this chapter, consisting of a `main` and a `check_buf` function. We want to fuzz test the `check_buf` function. For this purpose, we want to restructure the project so that the code we want to test is part of a library crate.

Initially, your project  probably consists of a Cargo project file (i.e., a Cargo.toml file) and a `main.rs`. The Cargo.toml specifies the name of the project, e.g. `your_project`.


```text
src/main.rs
Cargo.toml
```


We want to split the main.rs file into the entrypoint of the program, the main function, and the code we want to fuzz test. This results in the following files.


{{< customFigure "src/lib.rs" >}}
```Rust
use std::process;

pub fn check_buf(buf: &[u8]) {
    if buf.len() > 0 && buf[0] == b'a' {
        if buf.len() > 1 && buf[1] == b'b' {
            if buf.len() > 2 && buf[2] == b'c' {
                process::abort();
            }
        }
    }
}
```
{{< /customFigure >}}

{{< customFigure "src/main.rs" >}}
```Rust
fn main() {
    let buffer: &[u8] = b"123";
    your_project::check_buf(buffer);
}
```
{{< /customFigure >}}

The project is now structured in the following way.

```text
src/main.rs
src/lib.rs
Cargo.toml
```


The next step is to initialize the project using cargo-fuzz.


```shell
cargo fuzz init
```


This creates a new Cargo project in a `fuzz/` subdirectory, which depends on your Cargo crate. The directory `fuzz/fuzz_targets` contains Rust programs that use the [libfuzzer-sys](https://github.com/rust-fuzz/libfuzzer) dependency. We can adjust the default file generated at `fuzz_targets/fuzz_target_1.rs` directory to the following:


{{< customFigure "fuzz_targets/fuzz_target_1.rs" >}}
```Rust
#![no_main]

use libfuzzer_sys::fuzz_target;

fn harness(data: &[u8]) {
    your_project::check_buf(data);
}

fuzz_target!(|data: &[u8]| {
    harness(data);
});
```
{{< /customFigure >}}


The setup for cargo-fuzz is now done. We created a harness that can be executed by cargo-fuzz. The actual name of the fuzz target is defined in the `fuzz/Cargo.toml` file. Every fuzz test is a separate cargo binary.


## Usage {#usage}

Fuzz tests can be executed by invoking cargo-fuzz in the following way.


```shell
cargo +nightly fuzz run fuzz_target_1
```

If the project does not contain unsafe Rust or calls into C/C++ code, then we can append the option `--sanitizer none` to significantly improve the fuzzing performance. By default, AddressSanitizer is enabled, which checks for memory-related bugs. Because Rust is a memory-safe language, the usage of AddressSanitizer unnecessarily slows down the execution if no unsafe Rust is used (see the [AddressSanitizer](#addresssanitizer) section if you are unsure whether to enable or disable ASan for your use case).

The corpus is persisted in the `fuzz/corpus/fuzz_fuzz_target_1/` directory. Crashes are stored in `fuzz/artifacts/fuzz_fuzz_target_1/`.

### Re-execute a test case {#re-execute-a-test-case}

A test case can be re-executed using `cargo +nightly fuzz run fuzz_target_1 <test_case>`. For example, the following command re-executes a crash:


```shell
cargo +nightly fuzz run fuzz_target_1 fuzz/artifacts/fuzz_target_1/crash-04629f583cb62b4c23651a9b9b1749abbad5f932
```


This helps triage found bugs. If you want to re-execute a directory of test cases without actually fuzzing (`-runs=0`), you can run:

```shell
cargo +nightly fuzz run fuzz_target_1 <directory> -- -runs=0
```

For example, to re-execute the corpus you can run the following command:

```shell
cargo +nightly fuzz run fuzz_target_1 fuzz/corpus/fuzz_target_1 -- -runs=0
```

### Fuzzer options {#fuzzer-options}

Several options can be adjusted by adding command-line flags when running cargo-fuzz.


* **–-sanitizer none** Controls which sanitizers are enabled. ASan is enabled by default, which is helpful when fuzzing unsafe Rust code. If you are not using unsafe Rust, then sanitizers can be disabled to achieve a significant performance boost. (See the [AddressSanitizer](#addresssanitizer) section for more information.)


* **–-jobs 1** Enables the experimental forking features by libFuzzer, as briefly mentioned in [Multi-core Fuzzing]({{% relref "10-libfuzzer#multi-core-fuzzing" %}}). We do not recommend using this feature.

Apart from the cargo-fuzz specific options, libFuzzer options can be used by appending a `--` followed by the libFuzzer option. In the following example, we print all command-line options for libFuzzer:


```shell
cargo +nightly fuzz run fuzz_target_1 -- -help=1
```

For example, the following command allows one to specify a dictionary file that guides the fuzzer and allows the fuzzer to discover interesting test cases more quickly. (For more details about this, see [Fuzzing dictionary]({{% relref 02-dictionary %}}).)


```shell
cargo +nightly fuzz run fuzz_target_1 -- -dict=./dict.dict
```

## AddressSanitizer {#addresssanitizer}

ASan helps detect memory errors that might otherwise go unnoticed. For a general introduction to ASan, refer to [AddressSanitizer](#addresssanitizer).

ASan is enabled by default when fuzzing with cargo-fuzz. This may be a bad default if you are not using [unsafe Rust](https://doc.rust-lang.org/book/ch19-01-unsafe-rust.html) in your code or your dependencies. ASan may be unnecessary in this case because its goal is to detect memory corruption bugs, but Rust without unsafe code is memory-safe.  The [cargo-geiger](https://github.com/geiger-rs/cargo-geiger) project can help you determine if your project uses unsafe Rust.

A speedup of 2x can be expected from disabling ASan.

ASan can be disabled with the flag ​​`--sanitizer none`:


```shell
cargo +nightly fuzz run ​​--sanitizer none fuzz_target_1
```


Most sanitizers in Rust currently require a nightly toolchain because they are an [unstable](https://doc.rust-lang.org/beta/unstable-book/compiler-flags/sanitizer.html) feature as of writing. So if you encounter issues when compiling your project, you might want to test a different version of the installed nightly toolchain.



## Real-world examples {#real-world-examples}


### Cargo crate: ogg {#cargo-crate-ogg}

The ogg crate parses [ogg](https://en.wikipedia.org/wiki/Ogg) files, which contain media data. The ogg format is a container format for media, which means such files can host different codecs. Parsers are easy to fuzz and also a high-value target, because they have to behave correctly even when they are presented with untrusted data.

Let's go over the process of fuzzing an existing Cargo crate. First, we check out the source-code of the crate:

```shell
git clone https://github.com/RustAudio/ogg.git
cd ogg/
```


Now, we initialize cargo-fuzz:

```shell
cargo fuzz init
```

We look now for examples, unit tests, or integration tests in the project that might provide us with a good starting point for writing a harness, such as the [repack example](https://github.com/RustAudio/ogg/blob/5ee8316e6e907c24f6d7ec4b3a0ed6a6ce854cc1/examples/repack.rs) in the ogg crate. We rewrite this example to read and write to memory instead of to a file. Rust errors denoted by the `Result:Err(_)` enum case are ignored, because returning an error for invalid files generated by the fuzzer is good behavior. In case of an error, the current input is skipped (see the `if let Ok(r) = … {` statements).

The following code shows the harness and the entrypoint, stored at `fuzz/fuzz_targets/fuzz_target_1.rs` for cargo-fuzz.

{{< customFigure "Harness for the ogg library" >}}
```
#![no_main]

use ogg::{PacketReader, PacketWriter};
use ogg::writing::PacketWriteEndInfo;
use std::fs::File;
use std::io::Cursor;

use libfuzzer_sys::fuzz_target;

fn harness(data: &[u8]) {
    let mut data = data.to_vec();
    let mut pck_rdr = PacketReader::new(Cursor::new(data));

    pck_rdr.delete_unread_packets();

    let output = Vec::new();

    let mut pck_wtr = PacketWriter::new(Cursor::new(output));

    if let Ok(r) = pck_rdr.read_packet() {
        if let Ok(r) = pck_rdr.read_packet() {
            match r {
                Some(pck) => {
                    let inf = if pck.last_in_stream() {
                        PacketWriteEndInfo::EndStream
                    } else if pck.last_in_page() {
                        PacketWriteEndInfo::EndPage
                    } else {
                        PacketWriteEndInfo::NormalPacket
                    };
                    let stream_serial = pck.stream_serial();
                    let absgp_page = pck.absgp_page();
                    let _ = pck_wtr.write_packet(pck.data, stream_serial, inf, absgp_page);
                }
                // End of stream
                None => return,
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    harness(data);
});
```
{{< /customFigure >}}

To improve fuzzing performance, we can seed the fuzzer by downloading an initial test case:

```shell
mkdir fuzz/corpus/fuzz_target_1/
curl -o fuzz/corpus/fuzz_target_1/320x240.ogg https://commons.wikimedia.org/wiki/File:320x240.ogg
```


We can now run the fuzzer:


```shell
cargo +nightly fuzz run fuzz_target_1
```


The corpus is stored at `fuzz/corpus/fuzz_target_1/`. Check out the [FAQ]({{% relref "05-faq" %}}) to learn how to use a corpus over the long term.

The next step is to investigate the coverage and see if the harness or seed corpus can be improved (refer to the [Coverage analysis](#real-world-examples)).

## Additional resources {#additional-resources}

* [Rust Fuzz Book about cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html)
