---
title: "Semgrep"
weight: 2
summary: "Semgrep is a fast and open source static analysis tool for finding bugs, detecting vulnerabilities in third-party dependencies, and enforcing code standards."
bookCollapseSection: true
---

# Semgrep

Semgrep is a highly efficient static analysis tool for finding low-complexity bugs and locating specific code patterns.
Because of its ease of use, no need to build the code, multiple built-in rules, and convenient creation of custom rules,
it is usually the first tool to run on an audited codebase. Furthermore, Semgrep's integration into the CI/CD pipeline
makes it a good choice for ensuring code quality.

{{< hint info >}}🎥 Watch the Trail of Bits Webinar on [Introduction to Semgrep](https://www.youtube.com/watch?v=yKQlTbVlf0Q),
where we guide you on effectively bootstrapping Semgrep, the first section in this testing handbook{{< /hint >}}

## Benefits of using Semgrep

- Prevents re-entry of known bugs and security vulnerabilities
- Enables large-scale code refactoring, such as upgrading deprecated APIs
- Easily added to the CI/CD pipelines
- Custom Semgrep rules mimic the semantics of actual code
- Allows for secure scanning without sharing code with third parties, suitable for closed-source repositories
- Can be extended with new languages
  (see: [How Two Interns Are Helping Secure Millions of Lines of Code - Slack Engineering](https://slack.engineering/how-two-interns-are-helping-secure-millions-of-lines-of-code/))
  or built upon for creating new tools (e.g., [NodeJsScan](https://github.com/ajinabraham/nodejsscan) or [GuardDog](https://github.com/DataDog/guarddog))
- Scanning with Semgrep usually takes minutes (not hours/days)
- Semgrep is easy to use and accessible for both developers and security professionals,
  offering a seamless first-time experience for average users
- Semgrep has an open-source engine and rules
- Helps maintain high code quality standards and streamline the on-boarding of new developers

## Ideal use case

The following questions can help you determine if Semgrep is the right tool for finding a particular type of bug:

- Does Semgrep support the [languages](https://semgrep.dev/docs/supported-languages/#language-maturity)
or [technologies](https://semgrep.dev/docs/contributing/contributing-to-semgrep-rules-repository/#technology) in your project?
- Does the bug follow easy-to-identify patterns?
- Can you identify the bug by looking at single files?
- Can you spot the bug via intraprocedural (within a single file) analysis?
- Is the bug systemic (multiple instances across the codebase)?
- Do you want to detect the (lack of) use of secure defaults?

The following questions can help you determine if you can write a custom Semgrep rule for your problem:

- Can we detect a specific security vulnerability?
- Can we enforce best practices/conventions or maintain code consistency?
- Can we optimize the code by detecting code patterns that affect performance?
- Can we validate a specific business requirement or constraint?
- Can we identify deprecated/unused code?
- Can we spot any misconfiguration in a configuration file?
- Is this a recurring question as you review your code?
- How is code documentation handled, and what are the requirements for documentation?
- What are some common coding practices that are discouraged in your codebase?

Support for the following cases is currently limited. Although development is ongoing, Semgrep may not be able to handle:

- When multiple files are required for your analysis
  - Consider using the [Semgrep Pro Engine](https://semgrep.dev/docs/semgrep-code/semgrep-pro-engine-intro/)
- When you need advanced flow analysis
  - Familiarize yourself with the [Semgrep dataflow analysis engine](https://semgrep.dev/docs/writing-rules/data-flow/data-flow-overview/)
- Complex taint tracking
  - Check out the current state of
    [Semgrep taint tracking](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/) status
- If you have a custom, in-house framework that is not open source
