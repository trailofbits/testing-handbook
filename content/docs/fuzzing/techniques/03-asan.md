---
title: "AddressSanitizer"
slug: asan
weight: 3
---


### AddressSanitizer {#addresssanitizer}

AddressSanitizer (ASan) is a widely adopted tool in the realm of software testing, particularly during fuzzing. Fuzzing greatly benefits from the use of ASan because it helps detect memory errors that might otherwise go unnoticed, such as buffer overflows and use-after-free errors. 

While ASan is a standard practice in fuzzing due to its effectiveness in identifying such vulnerabilities, it does come with certain drawbacks. 



* One significant downside is that it can make the fuzzing process approximately 2–4 times slower. This reduction in speed is a tradeoff for the increased reliability and depth of testing.
* ASan is not well supported on platforms other than Linux (i.e., Windows and macOS).
* ASan maps a large amount of virtual memory from the operating system, typically requiring around 20TB. (This amount used to be 16TB, or 1/8th of the address space; [see AddressSanitizer: A Fast Address Sanity Checker](https://www.usenix.org/sites/default/files/conference/protected-files/serebryany_atc12_slides.pdf).) Because of this, you need to disable memory restrictions imposed by the fuzzer you use (e.g., `-rss_limit_mb 0` for libFuzzer and `-m none` for AFL++).


Despite these limitations, the benefits of using ASan during fuzzing to enhance software security and reliability by improving memory error detection capabilities often outweigh the drawbacks, making it a valuable tool in the software development lifecycle. 

Note that it can also make sense to enable ASan for your unit tests. However, do not use ASan during production, because it can [make applications actually less secure](https://www.openwall.com/lists/oss-security/2016/02/17/9). ASan is primarily a detection tool.

In general, ASan is enabled by using the flag `-fsanitize=address` during compilation and linking. However, integration can differ between fuzzers. Therefore, refer to the following sections:

* C/C++
    * [libFuzzer: AddressSanitizer](#addresssanitizer)
    * [AFL++: AddressSanitizer](#addresssanitizer)
* Rust: 
    * [cargo-fuzz: AddressSanitizer](#addresssanitizer)

ASan is documented on the [Google GitHub](https://github.com/google/sanitizers/wiki/AddressSanitizer). If you want to learn more about flags to configure ASan via the `ASAN_OPTIONS` environment variable, refer to [this page](https://github.com/google/sanitizers/wiki/SanitizerCommonFlags) for common sanitizer flags and [that page](https://github.com/google/sanitizers/wiki/AddressSanitizerFlags) for ASan flags specifically. An example configuration looks like this: 


```shell
ASAN_OPTIONS=verbosity=1:abort_on_error=1
```

The most commonly used flags are: 

* `verbosity=1`: Prints information before the actual program starts. Useful to check if a binary is sanitized by checking if output from ASan is printed.
* `detect_leaks=0`: Controls whether the [leak sanitizer](https://github.com/google/sanitizers/wiki/AddressSanitizerLeakSanitizer) is enabled. Leaks do not immediately lead to a crash in the fuzzer, but results about leaks are printed at the end of the fuzzing campaign.
* `abort_on_error=1`: Calls [`abort`](https://linux.die.net/man/3/abort) instead of [`_exit`](https://linux.die.net/man/3/_exit) after printing errors. This is useful for some fuzzers that require calling [`abort`](https://linux.die.net/man/3/abort).

The [FAQ on GitHub](https://github.com/google/sanitizers/wiki/AddressSanitizer#faq) summarizes the most common pitfalls when using ASan.

If you are using Clang refer to its [documentation](https://clang.llvm.org/docs/AddressSanitizer.html). If using GCC, then additionally refer to this [documentation](https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html#index-fsanitize_003daddress).