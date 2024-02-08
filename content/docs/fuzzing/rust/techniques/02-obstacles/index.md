---
title: "SUT patching: Overcoming obstacles"
slug: obstacles
weight: 2
---


##### SUT patching: Overcoming obstacles {#sut-patching-overcoming-obstacles}

Codebases are often not fuzzing-friendly. This can happen if, for example, the code uses checksums or depends on a global state like a system-time seeded PRNG (i.e., from the [rand](https://docs.rs/rand/latest/rand/)) that causes the code to behave differently for the same input. Refer to [Practical harness rules]({{% relref "01-writing-harnesses#practical-harness-rules" %}}) to learn more about potential problems in your SUT. If you encounter checksums or a global state in your SUT, you may want to apply fuzzing-specific patches to change the behavior of the program during fuzzing, as shown in the following. 

Rust fuzzers define a configuration option that is set during compilation of your Rust project. Similar to the [`cfg!(test)`](https://doc.rust-lang.org/reference/conditional-compilation.html#test) config option, the `cfg!(fuzzing)` option is enabled during fuzzing. You can use conditional compilation to overcome obstacles in your code, like hash checks that often hinder fuzzers at covering deeper code paths. The following figure shows an example.

{{< customFigure "Example usage of `cfg!(fuzzing)`" >}}
```Rust
if checksum != expected_hash {
    // Eliminate the need for guessing checksums by ignoring this error during fuzzing
    if !cfg!(fuzzing) {
        return Err(MyError::Hash)
    }
}

// Continue program execution
```
{{< /customFigure >}}



Note that this means that your SUT is behaving differently during fuzzing and production. Carelessly skipping checks can lead to false positives during fuzzing. For example, skipping the validation of a config file might lead to crashes in the SUT because the code expects config values to have a certain format. If the validation ensures that the config contains non-zero integers, then code called after the validation could misbehave when zero values are encountered. See the following example for an illustration.


{{< customFigure "Problematic usage of `cfg!(fuzzing)` that skips config validation. This may lead to false positives during fuzzing." >}}
```Rust
if !cfg!(fuzzing) {
    config.validate()?; // return error if config contains zero values
}

// assume no negative values exist

let result = 100 / config.x; // Can crash if validation is skipped
```

{{< /customFigure >}}

For instance, the ogg crate uses a `cfg!(fuzzing)` check to [perform checksum checks only if the project is not being fuzzed](https://github.com/RustAudio/ogg/blob/5ee8316e6e907c24f6d7ec4b3a0ed6a6ce854cc1/src/reading.rs#L298-L300). Adding a `cfg!(fuzzing)` check can increase fuzzing coverage greatly, but requires source code modifications.