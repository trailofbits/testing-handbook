---
title: "SUT patching: Overcoming obstacles"
slug: obstacles
weight: 2
---

# SUT patching: Overcoming obstacles {#sut-patching-overcoming-obstacles}

Codebases are often not fuzzing-friendly. This can happen if, for example, the code uses checksums or depends on a global state like a system-time seeded PRNG (i.e., by using [`rand`](https://man.archlinux.org/man/rand.3)) that causes the code to behave differently for the same input. Refer to [Practical harness rules]({{% relref "01-writing-harnesses#practical-harness-rules" %}}) to learn more about potential problems in your SUT. If you encounter checksums or a global state in your SUT, you may want to apply fuzzing-specific patches to change the behavior of the program during fuzzing, as shown in the following paragraphs. 

Typically, C/C++ fuzzers define the macro `FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`. This is at least true for libFuzzer, AFL++, LibAFL, and Hongfuzz. If the macro is defined, then the program is being compiled for fuzzing. By using conditional compilation based on that macro, you can overcome obstacles in your code, such as hash checks that often hinder fuzzers at covering deeper code paths. The following figure shows an example.




{{< customFigure "Example usage of `FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`" >}}
```C++
if (checksum != expected_hash) {
// Eliminate the need for guessing checksums by ignoring this error during fuzzing
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
  return -1;
#endif
}

// Continue program execution
```
{{< /customFigure >}}


Note that this means that your SUT is behaving differently during fuzzing and production. Carelessly skipping checks can lead to false positives during fuzzing. For example, skipping the validation of a config file might lead to crashes in the SUT because the code expects config values to have a certain format. If the validation ensures that the config contains non-zero integers, then code called after the validation could misbehave when zero values are encountered. See the following example for an illustration.



{{< customFigure "Problematic usage of `FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` that skips config validation. This may lead to false positives during fuzzing." >}}
```C++
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
if (!validate_config(&config)) {
    // return error if config contains zero values
    return -1;
}
#endif

// assume no negative values exist

int32_t result = 100 / config.x; // Can crash if validation is skipped
```
{{< /customFigure >}}

A real-world use of this variable occurs in the OpenSSL project, which [uses this variable](https://github.com/openssl/openssl/blob/afb19f07aecc84998eeea56c4d65f5e0499abb5a/crypto/cmp/cmp_vfy.c#L665-L678) to change how cryptographic algorithms work.
