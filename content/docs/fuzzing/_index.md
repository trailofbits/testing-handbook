---
title: "Fuzzing"
weight: 3
summary: "Fuzzing is ..."
bookFlatSection: true
---

# Fuzzing

Fuzzing represents a dynamic testing method that inputs malformed or unpredictable data to a system to detect security issues, bugs, or system failures. We consider it an essential tool to include in your testing suite.

This chapter of our Testing Handbook describes how to start fuzzing your project quickly. After covering the basics, we will dive deeply into more advanced fuzzing techniques and show you how to bring your testing setup to the next level. By the end of the chapter, you'll know how to choose applicable fuzzers, write fuzzing harnesses, understand their outputs, and apply them to real-world projects. The chapter can be followed step-by-step and completed within an afternoon.

The concept of fuzz testing dates back over 30 years, during which time it was used for examining UNIX command-line utilities (see [An empirical study of the reliability of UNIX utilities](https://dl.acm.org/doi/pdf/10.1145/96267.96279)). Since then, fuzzing has evolved from purely generating random input (blackbox fuzzing) to generating inputs based on feedback gathered while executing the tested program (graybox fuzzing). Because these utilities are written in C, we will start by describing how to fuzz C/C++ projects. Before that, though, we'll explain a bit about the intended audience and structure of this chapter.

## Audience and scope {#audience-and-scope}

This fuzzing chapter, just like the whole testing handbook, targets both developers and security engineers. Readers should already be comfortable with the programming language of the respective section and be familiar with common UNIX tools like Bash, Git, and cURL. Experience with Debian, Ubuntu, or any other Linux is required for following and executing the included examples.

First and foremost, the testing handbook is for engineers who test their own code. Therefore, the chapter focuses on fuzzing projects for which you have the source available. 

Even though we want to provide a starting point for fuzzing, we try to point to the relevant documentation if it is available, instead of reiterating what has been written over and over in countless other guides. Our guidance focuses on how to continue after a basic setup is working. Oftentimes the first iteration of a fuzzing setup can be improved easily by following techniques such as analyzing the code coverage.


## Structure {#structure}

We opted to give this chapter an expandable structure: For each language (e.g., C/C++, Rust, Go), we enumerate the fuzzers that can be used. We provide advice on which fuzzer to choose and then describe how to install it, compile a fuzz test, and use the fuzzer. If the fuzzer has special features, like multi-core fuzzing or support for 
[sanitizers](https://en.wikipedia.org/wiki/Code_sanitizer) <!-- TODO link our sanitizer section in the future -->, then we add those afterwards. Each fuzzer section finishes with real-world examples and further resources.

Each language section concludes with a language-specific "Techniques" subsection. If a technique applies to all languages and fuzzers, then it is listed in the [Techniques]({{% relref "/docs/fuzzing/techniques" %}}) section at the very end of the chapter. This very last section also contains an [FAQ]({{% relref "05-faq" %}}) and information about [Fuzzing environments]({{% relref 04-env%}}).

## Terminology {#terminology}


* **SUT/target:** The System Under Test (SUT) is the piece of software that is being tested. It can either be a standalone application like a command-line program or a library.
* **Fuzzing/Fuzzer:** Fuzz testing, also known as fuzzing, is an automated software testing method that supplies a SUT with invalid, unexpected, or random data as inputs. The program that implements the fuzzing algorithm is called a fuzzer.
* **Test case:** A test case is the concrete input that is given to the testing harness. Usually, it is a string or bitstring. A test input can also be encoded in a more complex format like an abstract syntax tree.
* **(Testing/fuzzing) harness:** A harness handles the test setup for a given SUT. The harness wraps the software and initializes it such that it is ready for executing test cases. A harness integrates a SUT into a testing environment.
* **libFuzzer harness:** A harness that is compatible with the libFuzzer library. The term refers to the `LLVMFuzzerTestOneInput` function.
* **Fuzz test:** A fuzz test consists of a fuzzing harness and the SUT. You might refer to a compiled binary that includes the harness and SUT as a fuzz test.
* **Fuzzing campaign:** A fuzzing campaign is an execution of the fuzzer. A fuzzing campaign starts when the fuzzer starts testing and stops when the fuzzing procedure is stopped.
* **Corpus:** The evolving set of test cases. During a fuzzing campaign, the corpus usually grows as new test cases are discovered.
* **Seed Corpus:** Fuzzing campaigns are usually bootstrapped using an initial set of test cases. This set is also called a seed corpus. Each test case of the corpus is called a seed.
* **Fuzzing engine/runtime:** The fuzzing engine/runtime is part of the fuzzer that is executed when the fuzzing starts. It orchestrates the fuzzing process.
* **Instrumentation:** The act of instrumenting a program involves adding non-functional changes in order to retrieve data from it or making it more secure/robust.
* **Code coverage:** A metric to measure the degree to which the source code of a program is executed.
{.no-bullet-point-list}

## Pros and cons of fuzzing {#pros-and-cons-of-fuzzing}

Fuzzing offers several benefits and limitations compared to other testing strategies like manual code audits or unit testing:

|Advantages|Disadvantages|
|--- |--- |
|**Finds overlooked vulnerabilities:** With a broad coverage of the input space, fuzzers can find bugs that were not identified during manual checks.|**Complex inputs pose challenges:** For software requiring complex input (i.e., network packets like TLS or source code), developing an efficient fuzzer with good code coverage requires significant effort.|
|**Automation and scalability:** Once operational, a fuzzer can search for flaws over extended periods of time—ranging from hours to months.|**Incomplete bug detection:** Fuzzing may not catch all bugs, especially those that don't cause the program to crash or are triggered under very specific conditions.|
|**Cost-effective:** Although there's an initial setup cost, over time, fuzzing is cost-effective compared to manual testing.|**Traditionally focused on memory-corruption bugs:** Traditionally, fuzzing focused on finding program crashes caused by memory corruption that are not possible with memory-safe languages like Rust or Go. However, the fuzzing community is slowly shifting towards finding logic bugs as well.|
|**Proven technique for finding memory corruption bugs:** Fuzzing has found thousands and thousands of bugs related to memory management. It has proven itself a must-have tool for memory-unsafe languages.||
{.hide-empty-cells}

The first step when fuzzing a software package is assessing the fuzz-worthy targets in the package. This is because fuzzing works particularly well with certain code structures and can be more involved with other structures. For instance, fuzzing a parser is straightforward: fuzzing is easy to set up, and finding bugs is very likely. If your project implements complex application logic and is not easily testable (i.e., it does not yet have unit tests), then you might derive greater benefit from a static analyzer, proper unit testing, and manual code review. After these testing techniques have been implemented, the next step could be to fuzz your code!

Fuzzing is no silver bullet, just like unit tests or static analysis aren't. We are currently working on a section that compares static and dynamic analysis tools to fuzzing. Stay tuned for an update on that! <!-- TODO: Link when comparision section is done! -->

Before we introduce typical fuzzing setups, we first want to explain today's default fuzzing strategy: mutation-based evolutionary fuzzing.


## The default fuzzing algorithm is mutation-based  and evolutionary {#the-default-fuzzing-algorithm-is-mutation-based-and-evolutionary}

The original [AFL](https://lcamtuf.coredump.cx/afl/) fuzzer employed a fuzzing algorithm inspired by evolutionary algorithms. This algorithm is the de facto algorithm for fuzzers.

The basic idea is to maintain a population of test cases in a corpus. Each test case within the corpus has a certain fitness—analogous to the biological theory. This can be determined by using a coverage metric to denote the fitness of a test case. An evolutionary algorithm then schedules fit test cases and applies mutations to produce offspring. Each new mutated test case is executed, and a fitness is assigned. The idea is to only allow offspring that are beneficial in terms of fitness to survive. The following section explains this evolutionary process more closely.


{{< customFigure "Pseudocode that illustrates an evolutionary-based fuzzer" >}}
```Rust  {linenos=inline}
fn fuzz(corpus) {
  let bug_set = []; // We start with an empty set
  while let Some(test_case) = schedule(corpus) { // Now, we pick one test case after the other
    let offspring = mutate(test_case); // Each test case is mutated to create offspring
    let observations = execute(offspring); // New test cases are executed

    if (is_interesting(observations)) {
      corpus.append(offspring); // If the observations are interesting we keep the new test case
    }
    if (is_bug(observations)) {
      bug_set.append(offspring); // If the observations indicate that a bug occured then we store the test case
    }
  }
  return bug_set; // The set of bugs is returned
}
```
{{< /customFigure >}}

**Fuzzing input:** The above pseudocode describes the steps that are executed during a fuzzing campaign. Line 1 shows that we expect an initial corpus as input. We require that the initial corpus is not empty. We also start with an empty bug set in the first line of the function. During the fuzzing campaign, the bug set collects test cases that triggered a bug.

**`schedule(test_case)`:** In line 3, we start the fuzzing loop by scheduling one test case after the other from the corpus. The `schedule` function eventually decides to stop the fuzzing campaign by returning nothing. This could happen after, for example, a set amount of iterations.

**`mutate(test_case)`:** In line 4, we mutate the test case to create offspring. Mutations can change test cases in various ways. If the test inputs are byte arrays, then common mutation strategies include flipping bits in the byte array, inserting new bytes in the byte arrays or truncating it.

**`execute(test_case)`:** In line 5, we execute the new test case in order to generate observations. The simplest observation is the time it took to execute the mutated test case. More complex observations could include the covered lines of code within the SUT.

**Fuzzing output:** In lines 8 and 11, we increase either the corpus or bug set, respectively, if the observations indicate an interesting behavior of the offspring or if a bug was observed.

In other words: if something represents progress toward finding bugs, then we add it to the corpus. In analogy to the evolutionary algorithm, this means that we favor fit offspring. Traditionally, the interestingness of a test case coincides with increases in code coverage.

After the fuzzing campaign finishes, the found bugs are returned.


## Introduction to fuzzers {#introduction-to-fuzzers}

Every fuzzing setup consists of an instrumented System Under Test (SUT),  the fuzzing harness, and the fuzzer runtime. A runtime for the instrumentation may also be required. For example, the optional [AddressSanitizer]({{% relref 03-asan %}}) (ASan) instrumentation adds a runtime that is used to detect [memory corruption bugs](https://en.wikipedia.org/wiki/Memory_corruption) like [heap-buffer overflows](https://en.wikipedia.org/wiki/Heap_overflow) more reliably. The following figure shows the standard fuzzing setup.

{{< resourceFigure "intro.svg" >}}
The general fuzzing scenario consists of the developer writing a harness for a SUT. After starting a fuzzing campaign, the fuzzer runtime generates random test cases that are sent to the harness. The harness then executes the SUT, which could lead to the discovery of bugs and crashes. Instrumentation runtime and the instrumentation added to the SUT are generally optional, even though most fuzzers instrument the SUT code and add a runtime.
{{< /resourceFigure >}}

**SUT (System Under Test):** This is the code you want to test. To create a fuzzing build of your SUT, you need to control how the application's code is compiled and linked. The following figure shows a very simple SUT that serves as a running example throughout this chapter of the Testing Handbook.

{{< customFigure "Pseudocode that illustrates an evolutionary-based fuzzer" "html" >}}
{{< tabs "sut" >}}
{{< tab "C/C++" >}}
```C++
#include <stdlib.h>
#include <string.h>

void check_buf(char *buf, size_t buf_len) {
    if(buf_len > 0 && buf[0] == 'a') {
        if(buf_len > 1 && buf[1] == 'b') {
            if(buf_len > 2 && buf[2] == 'c') {
                abort();
            }
        }
    }
}

#ifndef NO_MAIN
int main() {
    char target[] = "123";
    size_t len = strlen(target);
    check_buf(target, len);
    return 0;
}
#endif // NO_MAIN
```
main.cc (C/C++): Example SUT with a bug that causes an abort. The `check_buf` funciton aborts for the input "abc".
{{< /tab >}}

{{< tab "Rust" >}}
```Rust
use std::process;

fn check_buf(buf: &[u8]) {
    if buf.len() > 0 && buf[0] == b'a' {
        if buf.len() > 1 && buf[1] == b'b' {
            if buf.len() > 2 && buf[2] == b'c' {
                process::abort();
            }
        }
    }
}

fn main() {
    let buffer: &[u8] = b"123";
    check_buf(buffer);
}
```
main.rs (Rust): Example code with a bug that causes an abort. The `check_buf` funciton aborts for the input "abc".
{{< /tab >}}
{{< /tabs >}}
{{< /customFigure >}}


**Harness:** The harness is the entrypoint for your fuzz test. The fuzzer calls this function with random —or carefully mutated—data. For tips and tricks for writing and using harnesses, refer to [Writing harnesses]({{% relref "/docs/fuzzing/techniques/01-writing-harnesses" %}}) and [Practical harness rules]({{% relref "/docs/fuzzing/techniques/01-writing-harnesses#practical-harness-rules" %}}).



{{< customFigure "Pseudocode that illustrates an evolutionary-based fuzzer" "html" >}}
{{< tabs "harness" >}}
{{< tab "C/C++" >}}
```C++
#include <stdint.h>

void check_buf(char *buf, size_t buf_len);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  check_buf((char*) data, size); // Invoke the SUT; in our case that is the check_buf function
  return 0; // Return 0, which means that the test case was processed correctly
}
```
harness.cc (C/C++): Entrypoint for the fuzzer

The de facto libFuzzer API is called LLVMFuzzerTestOneInput. The function receives a byte buffer and a length and returns 0. Return values are fuzzer-defined. In the case of libFuzzer, values other than 0 and -1 are reserved. Returning -1 skips the current test case and avoids adding it to the corpus. AFL++ ignores return values. LibAFL classifies test input as a bug if -2 is returned.
{{< /tab >}}

{{< tab "Rust" >}}
```Rust
fn harness(data: &[u8]) {
    check_buf(data);
}
```
harness.rs (Rust): Entrypoint for the fuzzer

There is no standard in the Rust ecosystem for the function signature of a harness. To remain generic, let's pretend a Rust fuzzing harness is a void function that receives a byte array with random data of Rust type `&[u8]`.
{{< /tab >}}
{{< /tabs >}}
{{< /customFigure >}}

Many techniques can be leveraged when writing harnesses; we discuss these in the [Writing harnesses]({{% relref "docs/fuzzing/techniques/01-writing-harnesses" %}}) section. You also need to be aware of certain [rules]({{% relref "docs/fuzzing/techniques/01-writing-harnesses#practical-harness-rules" %}}) that forbid certain code from being executed in a harness.

**Fuzzer runtime:** The fuzzing loop is implemented here. This unit also provides the main function for the fuzzer. The fuzzing runtime parses fuzzing options, executes the harness, collects feedback, and manages the fuzzer state. The runtime is provided by the fuzzing project you use, such as libFuzzer or AFL++. Any runtime that is required for collecting feedback through instrumentations is implemented in the fuzzer runtime.

**Instrumentation runtime:** Instrumentations like [AddressSanitizer]({{% relref 03-asan %}}) or [UndefinedBehaviorSanitizer](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html) come with a runtime. A fuzzer must be compatible with the sanitizer for bugs to be detected reliably and feedback implemented efficiently. In memory-safe languages like Go or Rust you are less likely to need sanitizers.

Note, that the two just mentioned sanitizers introduce instrumentation with the goal of finding more bugs. There is also a different class of instrumentations (e.g., [SanitizerCoverage](https://clang.llvm.org/docs/SanitizerCoverage.html)) that provides feedback to the fuzzer during execution. The runtime of the feedback-based instrumentation is usually part of the fuzzer runtime.
