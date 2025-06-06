---
title: "CodeQL"
weight: 2
summary: "CodeQL is a static analysis tool that transforms code into a relational database, and provides a custom declarative language to query this database."
bookCollapseSection: true
---

# CodeQL

CodeQL is a powerful static analysis framework that allows developers and
security researchers to query a codebase for specific code patterns. The
CodeQL standard libraries are included with the installation and implement
support for both inter- and intraprocedural control flow and data flow analysis.
However, be aware that the learning curve for writing your own custom queries
is steep, and documentation for the CodeQL standard libraries is still scant.

{{< hint info >}}🎥 Watch the Trail of Bits Webinar on
[Introduction to CodeQL: Examples, Tools and CI Integration](https://www.youtube.com/watch?v=rQRlnUQPXDw),
where we show you how we used CodeQL to find real-world security issues,
the tools needed for an effective CodeQL experience, and how to set up your CodeQL CI integration
{{< /hint >}}

{{< hint danger >}}

If you are planning to run CodeQL on a closed-source repository, you may need
a GitHub Enterprise or GitHub Advanced Security license. (For details, see the
[CodeQL installation instructions](https://docs.github.com/en/code-security/codeql-cli/getting-started-with-the-codeql-cli/setting-up-the-codeql-cli#1-download-the-codeql-cli-zip-package)
and the
[CodeQL license](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md).)

{{< /hint >}}

## Benefits of using CodeQL

- Supports interprocedural control flow and data flow queries across the entire
  codebase
- Allows for fine-grained control over the abstract syntax tree, control flow
  graph, and data flow graph
- Comes with a large set of libraries and predefined queries for each supported
  language
- Prevents the introduction of known bugs and security vulnerabilities into the
  codebase
- Easily added to CI/CD pipelines

## Ideal use case

The following questions can help answer whether CodeQL is the right tool to
identify variants of a given bug type:

- Do you have access to the source code and any third-party dependencies, and
  (for compiled languages) can you build the project?
- Are you analyzing an open-source codebase, or is the use of CodeQL covered by
  a GitHub Enterprise or GitHub Advanced Security license?
- Does CodeQL [support the languages](https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks)
  used in your project?
- Does the bug class require either fine-grained control of the abstract syntax
  tree, or interprocedural control flow or data flow analysis to express?
- Is analysis time not important? (Complex, interprocedural queries may
  take a long time to run.)

If the answer to any of these questions is "no," we recommend that you start
out by attempting to model the bug class using a tool like [Semgrep]({{% relref
"semgrep" %}}) instead.
