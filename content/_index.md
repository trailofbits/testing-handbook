---
title: Introduction
summary: "The automated testing handbook is a resource that guides developers and security professionals in configuring, optimizing, and automating many of the static and dynamic analysis tools we use at Trail of Bits."
weight: 1
---

# Trail of Bits Testing Handbook

<!-- markdown-link-check-disable -->
The Testing Handbook is a resource that guides developers and security
professionals in configuring, optimizing, and automating many of the static and
dynamic analysis tools we use at [Trail of Bits](https://www.trailofbits.com/).
<!-- markdown-link-check-enable -->
In our day-to-day work, we audit software projects ranging from cloud-native software
to embedded devices. We often find issues that should be easy to spot early in
development with the correct security tooling, but that make their way across
the software lifecycle undetected.

We hope to assist development teams across technology stacks in their quest to
improve the security posture of their software by providing practical
documentation they can apply when performing security analyses of their codebases.

{{< columns >}}

## Straightforward

We aim to make it as straightforward as possible to set up security tools
effectively across all steps of the software development lifecycle.

<--->

## Demystified

In doing so, we also hope to demystify static and dynamic analysis techniques
such as fuzzing and taint analysis.

{{< /columns >}}

## Why is this needed?

- The documentation for configuring and optimizing existing tools is often not
  developer friendly, as it is often targeted at security professionals. This
  is especially the case with fuzzing utilities. This lack of
  easy-to-follow documentation can lead to frustration and poor adoption of
  security tools that should be straightforward to configure.
- Even if the tool is easy to configure locally, it can be difficult to
  configure it in a CI/CD pipeline.
- Often, security tools are set up by following the online documentation, but
  their configuration is rarely optimized. This lack of tuning can lead to noisy
  tool results that are more frustrating than they are helpful.

## Tools

We currently cover the following tools and techniques:

{{< columns >}}

### Static analysis

- [Semgrep]({{< relref "semgrep" >}})
- [CodeQL]({{< relref "codeql" >}})

<--->

### Dynamic analysis

- [Fuzzing]({{< relref "fuzzing" >}})
- [Burp Suite Professional]({{< relref "/docs/web/burp/" >}})

{{< /columns >}}

We are working on expanding the tools we cover here. We are also planning to
cover several dynamic analysis tools. Stay tuned for updates from our team!

### Upcoming (!)

- Formal verification and Tamarin
- Rust security
- How to apply taint analysis in a directed fuzzing loop or/and for results verification
- Taking effective notes for security engagements
- mitmproxy
- Leveraging grep in security audits

## Custom queries for static analysis tools

One of our core objectives at Trail of Bits is to uncover and solve problems that are likely to recur.
This is where our custom queries come into play. Built on the knowledge and expertise of our entire team,
they provide proactive, effective security for your software projects.

{{< details title="[Trail of Bits public Semgrep rules](https://github.com/trailofbits/semgrep-rules)" open=true >}}
Navigate to the root folder of your project and use them right away:

```sh
semgrep --config "p/trailofbits"
```

{{< /details >}}

{{< details title="[Trail of Bits public CodeQL queries](https://github.com/trailofbits/codeql-queries)" open=true >}}
To install our public CodeQL queries for C, C++ and Go, simply run `codeql pack download`:

```sh
codeql pack download trailofbits/cpp-queries trailofbits/go-queries
```

To run our queries for C and C++ on an existing database, you can now run the following command:

```shell
codeql database analyze codeql.db --format=sarif-latest --output=results.sarif -- trailofbits/cpp-queries
```

{{< /details >}}

## Custom fuzzers

We make extensive use of fuzzing when auditing software for bugs. To that end,
we often build our own fuzzers when we cannot find one for the task at hand. The
following is a list of fuzzers we have built and endorse using:

- [Mishegos](https://github.com/trailofbits/mishegos): a differential fuzzer for x86 decoders
- [Ruzzy](https://github.com/trailofbits/ruzzy): a coverage-guided fuzzer for pure Ruby code and Ruby C extensions
- [Medusa](https://github.com/crytic/medusa): a parallelized, coverage-guided, mutational Solidity smart contract fuzzer
- [Echidna](https://github.com/crytic/echidna): Ethereum smart contract fuzzer
- [Tayt](https://github.com/crytic/tayt): StarkNet smart contract fuzzer

## Feedback
<!-- markdown-link-check-disable -->
We want to actively maintain the highest possible quality and expand the content of the Testing Handbook.
If you see a way to improve the Testing Handbook, please let us know! The best way to let us know is
by raising an issue directly on the [Testing Handbook GitHub page](https://github.com/trailofbits/testing-handbook).
<!-- markdown-link-check-enable -->
