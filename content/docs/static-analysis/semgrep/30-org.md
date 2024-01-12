---
title: "In your organization"
slug: in-your-organization
summary: "This section discusses the process of introducing Semgrep to your organization."
weight: 30
---

# How to introduce Semgrep to your organization

Semgrep is designed to be flexible to fit your organization’s specific needs. To get the best results, it’s important to
understand how to run Semgrep, which rules to use, and how to integrate it into the CI/CD pipeline. If you are unsure
how to get started, here is our seven-step plan to determine how to best integrate Semgrep into your SDLC, based on
what we’ve learned over the years.

## The 7-step Semgrep plan

1. Review the list of supported languages to understand whether [Semgrep can help you](https://semgrep.dev/docs/supported-languages/#language-maturity).

2. **Explore**: Try Semgrep on a small project to evaluate its effectiveness. For example, navigate into the root
directory of a project and run:

    ``` shell
    semgrep --config auto
    ```

    There are a few important notes to consider when running this command:

    - The `--config auto` option submits metrics to Semgrep, which may not be desirable.
    - Invoking Semgrep in this way will present an overview of identified issues, including the number and severity.
      In general, you can use this CLI flag to gain a broad view of the technologies covered by Semgrep.
    - Semgrep identifies programming languages by file extensions rather than analyzing their contents.
      Some paths are excluded from scanning by default using the default `.semgrepignore` file. Additionally, Semgrep
      excludes untracked files listed in a `.gitignore` file.

3. **Dive deep**: Instead of using the auto option, use the [Semgrep Registry](https://semgrep.dev/explore) to select
rulesets based on key security patterns, and your tech stack and needs.
   - Try:

        ```shell
        semgrep --config p/default
        semgrep --config p/owasp-top-ten
        semgrep --config p/cwe-top-25
        ```

        or choose a ruleset based on your technology:

        ```shell
        semgrep --config p/javascript
        ```

   - Focus on rules with high confidence and medium- or high-impact metadata first. If there are too many results,
   limit results to error severity only using the `--severity ERROR` flag.
   - Resolve identified issues and include reproduction instructions in your bug reports.

4. **Fine-tune**: Obtain your ideal rulesets chain by reviewing the effectiveness of currently used rulesets.
   - Check out non-security rulesets, too, such as best practices rules. This will enhance code readability and may
   prevent the introduction of vulnerabilities in the future. Also, consider covering other aspects of your project:
        - Shell scripts, configuration files, generic files, Dockerfiles
        - Third-party dependencies (Semgrep Supply Chain, a paid feature, can help you detect if you are using the
        vulnerable package in an exploitable way)
   - To ignore the incorrect code pattern by Semgrep, use a comment in your code on the first line of a preceding line
   of the pattern match, e.g., `// nosemgrep: go.lang.security.audit.xss`. Also, explain why you decided to disable
   a rule or provide a risk-acceptance reason.
   - Create a customized `.semgrepignore` file to reduce noise by excluding specific files or folders from the Semgrep
   scan. Semgrep ignores files listed in `.gitignore` by default. To maintain this, after creating a `.semgrepignore`
   file, add `.gitignore` to your `.semgrepignore` with the pattern `:include .gitignore`.

5. Create an internal repository to aggregate custom Semgrep rules specific to your organization.
A README file should include a short tutorial on using Semgrep, applying custom rules from your repository,
and an inventory table of custom rules. Also, a contribution checklist will allow your team to maintain the quality
level of the rules (see the
[Trail of Bits Semgrep rule development checklist](https://github.com/trailofbits/semgrep-rules/blob/main/CONTRIBUTING.md#development-practices)).
Ensure that adding a new Semgrep rule to your internal Semgrep repository includes a peer review process
to reduce false positives/negatives.

6. **Evangelize**: Train developers and other relevant teams on effectively using Semgrep.
    - Present pilot test results and advice on improving the organization's code quality and security.
    Show potential Semgrep limitations (single-file analysis only).
    - Include the official [Learn Semgrep](https://semgrep.dev/learn) resource and present the
    [Semgrep Playground](https://semgrep.dev/playground/new) with “simple mode” for easy rule creation.
    Provide an overview of how to write custom rules and emphasize that writing custom Semgrep rules is easy. Mention
    that the custom rules can be extended with the auto-fix feature using the `fix:` key. Encourage using metadata
    (i.e., CWE, confidence, likelihood, impact) in custom rules to support the vulnerability management process.
    To help a developer answer the question, “Should I create a Semgrep rule for this problem?” you can use these
    follow-up questions:
        - Can we detect a specific security vulnerability?
        - Can we enforce best practices/conventions or maintain code consistency?
        - Can we optimize the code by detecting code patterns that affect performance?
        - Can we validate a specific business requirement or constraint?
        - Can we identify deprecated/unused code?
        - Can we spot any misconfiguration in a configuration file?
        - Is this a recurring question as you review your code?
        - How is code documentation handled, and what are the requirements for documentation?
    - Create places for the team to discuss Semgrep, write custom rules, troubleshoot (e.g., a Slack channel),
    and jot down ideas for Semgrep rules (e.g., on a Trello board). Also, consider writing custom rules for bugs found
    during your organization’s security audits/bug bounty program. A good idea is to aggregate quick notes to help your
    team use Semgrep (see the [Appendix in the original blog post](https://blog.trailofbits.com/2024/01/12/how-to-introduce-semgrep-to-your-organization/#:~:text=Appendix%3A%20Things%20I%20wish%20I%E2%80%99d%20known%20before%20I%20started%20using%20Semgrep)).
    - Pay attention to the Semgrep Community Slack, where the Semgrep community helps with problems or writing custom
    rules.
    - Encourage the team to report existing limitations/bugs while using Semgrep to the Semgrep team by filling out
    GitHub issues (see this [example issue](https://github.com/returntocorp/semgrep/issues/4587) submitted by
    Trail of Bits).

7. Implement Semgrep in the CI/CD pipeline by getting acquainted with the Semgrep documentation related to your CI
vendor. Incorporating Semgrep incrementally is important to avoid overwhelming developers with too many results. So,
try out a pilot test first on a repository. Then, implement the full Semgrep scan on a schedule on the main branch in
the CI/CD pipeline. Finally, include a diff-aware scanning approach when an event triggers (e.g., a pull/merge request).
A diff-aware approach scans only changes in files on a trigger, maintaining efficiency. This approach should examine a
fine-tuned set of rules that provide high confidence and true positive results. Once the Semgrep implementation is
mature, configure Semgrep in the CI/CD pipeline to block the PR pipeline with unresolved Semgrep findings.

## What’s next? Maximizing the value of Semgrep in your organization

As you introduce Semgrep to your organization, remember that it undergoes frequent updates. To make the most of its
benefits, assign one person in your organization to be responsible for analyzing new features (e.g., Semgrep Pro, which
extends codebase scanning with inter-file coding paradigms instead of Semgrep’s single-file approach), informing
the team about external repositories of Semgrep rules, and determining the value of the paid subscription (e.g., access
to premium rules).
