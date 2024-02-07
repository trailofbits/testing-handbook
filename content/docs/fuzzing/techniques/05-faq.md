---
title: "FAQ (Fuzzily Asked Questions)"
slug: faq
summary: "TODO"
weight: 5
---

# FAQ (Fuzzily Asked Questions) {#faq-fuzzily-asked-questions}

## The fuzzer is showing crashes, but when I run the SUT on the test cases outside of the fuzzer, then no crash is shown. What is happening?

There are several potential reasons:


- The SUT is behaving nondeterministically.
- The SUT depends on global state (e.g., it may read or write to disk or use in-memory singletons).
- You are experiencing crashes because your system is running out of memory and killing processes. This is typically signaled by signal 6 on Linux. You may also want to check the output of `dmesg` and see if you have entries about out-of-memory issues. 


## When should I stop fuzzing?

This question is very hard to answer. The code coverage is essentially the only metric available in today's fuzzers. Code coverage is a proxy for measuring a fuzzer’s efficiency in finding bugs.

However, we have acknowledged that code coverage is the only tool we have nowadays. So the practical answer to the question is: Stop fuzzing when the fuzzer does not find new test cases for several hours. This is equivalent to saying that the fuzzer is not increasing its coverage.

Even though most academic papers about fuzzing run campaigns for 24 hours (see [Evaluating Fuzz Testing](https://arxiv.org/abs/1808.09700), Table 1 and section 6), there is no fixed recommendation for a specific duration. Running the fuzzer for longer can be beneficial. Experiment with longer durations than 24 hours and observe the fuzzing campaign.

Definitely keep in mind that the total count of executions is a more important metric than time. If your SUT is slow to execute, fuzz longer. Do not blindly stick to a specific time.

Also, based on our experience at Trail of Bits, we recommend running multiple fuzzing campaigns, periodically resetting the corpus, and verifying if the coverage has changed. Doing so supports the fuzzer when it encounters difficulties in exploring additional program states, attributed to the absence of sufficiently informative feedback or feedback that adequately guides the fuzzer's exploration process. Restarting a fuzzing campaign could result in randomly exploring different parts of the program than in previous campaigns.

## Should I keep the corpus confidential or make it public?

By default, you should keep the corpus confidential. The corpus is a valuable resource, and generating one takes a lot of effort. An attacker who is provided a corpus may find vulnerabilities more easily.

However, a number of projects, such as OpenSSL, decided to make their [corpora public](https://github.com/openssl/fuzz-corpora/). The probable reason for this is to support security researchers. Also, it simplifies the setup of using the corpus for fuzzing in CI.

In conclusion, this is a risk assessment you have to make for your project. We recommend starting by keeping the corpus private and then eventually making it public.

## My fuzzer is not finding anything. What are indicators that there is a bug in the fuzzing setup?

Take a look at the code coverage you achieve when fuzzing. In this fuzzing chapter, we have guides on how to check the coverage for every discussed fuzzer.

A proxy for code coverage can be the executions per second:
- If you are seeing too many (>10⁶ executions per second), then the critical code is probably not executing and the code coverage is likely low. The SUT may be hitting an error early and returning gracefully.
- If you are seeing not enough executions per second (<100), your target may be executing too slowly and the fuzzer is not progressing quickly enough to discover interesting test cases.


## My corpus has grown quite large. How do I deal with these thousands of small files?

There is a technique called “corpus minimization”.
Stay tuned for an update of the testing handbook to find out how to maintain and manage corpora! Subscribe to our newsletter [here](https://trailofbits.us4.list-manage.com/subscribe?u=3c3cd5fe83443b48332fb203f&id=ec54fc0dbd) to get notified.

## My fuzzer found inputs that crash the SUT. However, it is very large and complex. Is there a way to simplify finding the root cause of the crash?

A technique called “test case minimization” reduces the size of inputs while preserving the crash.

Stay tuned for an update to the testing handbook that will cover how to maintain and manage corpora! Subscribe the newsletter [here](https://trailofbits.us4.list-manage.com/subscribe?u=3c3cd5fe83443b48332fb203f&id=ec54fc0dbd) to get notified.

## How can I collect core dumps from crashes during or after a fuzzing campaign?

On Linux, two main settings affect core dumps: 1) the “core” [resource limit](https://linux.die.net/man/2/setrlimit) that enables core dumps per process, and 2) the `sysctl` setting [`kernel.core-pattern`](https://docs.kernel.org/next/admin-guide/sysctl/kernel.html#core-pattern), which determines where the core dump is stored or sent to.
For the Bash shell, you can use `ulimit -c` to query the current limits on core dumps; use `ulimit -c 0` to disable them and `ulimit -c unlimited` to enable them. The default for resource limits differs between environments and operating systems (i.e., server vs. desktop operating systems). In order to store core dumps in the current working directory in a file called `core`, you can configure the kernel using:

```shell
sysctl -w kernel.core_pattern=core
```

Depending on how you execute the crashing program, you may still not get a core dump file; fuzzers can interfere with the creation of core dumps either by setting the resource limits for the current process or by avoiding the creation of core dumps by overwriting signal handlers. Fuzzers disable core dumps because they may take a long time to create. Ideally, fuzzers want to continue fuzzing quickly after a crash is encountered.

Consult the documentation of your fuzzer to verify how to re-enable core dumps if you need them for debugging. Make sure to configure resource limits and the `kernel.core_pattern`.

For libFuzzer, AFL++, and Hongfuzz, follow this guidance:

- **libFuzzer.** By default, libFuzzer disables core dumps by registering signal handlers. To enable writing core dumps, you must [enable ASan]({{% relref "10-libfuzzer#addresssanitizer" %}}) and then set the environment variable `ASAN_OPTIONS=abort_on_error=1:disable_core dump=0`. Note that this works only for crashes that are handled by ASan. A call to [`abort`](https://linux.die.net/man/3/abort) does not cause the creation of a core dump with this method.
- **AFL++.** Set the `AFL_DEBUG` environment variable to `1` (see the source code for this option [here](https://github.com/AFLplusplus/AFLplusplus/blob/0c054f520eda67b7bb15f95ca58c028e9b68131f/src/afl-forkserver.c#L891)).
- **Hongfuzz.** Set the flag [`--rlimit_core`](https://github.com/google/honggfuzz/blob/348a47213919f14b9453e89a663b1515369bd9a2/docs/USAGE.md?plain=1#L170-L171) to a high value.


## I have a fuzzing setup. How often and where should I run my harness?

Ideally, you fuzz continuously on dedicated servers and in the continuous integration service you are already using.

Stay tuned for an update to the testing handbook to find out how to set up continuous fuzzing! Subscribe to the newsletter [here](https://trailofbits.us4.list-manage.com/subscribe?u=3c3cd5fe83443b48332fb203f&id=ec54fc0dbd) to get notified.

## My fuzzer has found multiple crashes. In fact, I have hundreds of crash files. How can I find the corresponding bugs? 

The process of pinpointing specific bugs is called “bug triaging.”

Stay tuned for an update to the testing handbook to find out how to triage bugs! Subscribe to the newsletter [here](https://trailofbits.us4.list-manage.com/subscribe?u=3c3cd5fe83443b48332fb203f&id=ec54fc0dbd) to get notified.

## How do I fuzz my Go, Python, Java, or JavaScript project?

Stay tuned for an update to the testing handbook to find out how to use the right tools for your technology stack! Subscribe to the newsletter [here](https://trailofbits.us4.list-manage.com/subscribe?u=3c3cd5fe83443b48332fb203f&id=ec54fc0dbd) to get notified and message [@trailofbits](https://twitter.com/trailofbits).

## I’m using Bazel, Buck, or some other build system. How can I integrate fuzzing into my project?

Message [@trailofbits](https://twitter.com/trailofbits) and tell us about your project setup. We’d be happy to check if there is an easy way to integrate the preferred fuzzer.

## My program runs only on Windows. How can I fuzz it?

Stay tuned for an update to the testing handbook to find out how to fuzz on Windows. Subscribe to the newsletter [here](https://trailofbits.us4.list-manage.com/subscribe?u=3c3cd5fe83443b48332fb203f&id=ec54fc0dbd) to get notified and message [@trailofbits](https://twitter.com/trailofbits) to let us know you want to fuzz on Windows.