---
title: "Supply chain analysis"
slug: rust-supply-chain-analysis
summary: "This section describes tricks for Rust unit testing"
weight: 40
---

# Supply chain analysis

## Vetting

The tools in this section are more for "understanding" than "checking." E.g., running them does not produce "bug reports", but can help you assess maturity and security of dependencies. Tools below are rather "quantitative" than "qualitative" - you will need to do manuall, in-depth review of the outputs to extract any solid evidences about the maturity.

 Run cargo-supply-chain
This reveals who you are implicitly trusting when you rely on a dependency (e.g., you want that set to be small)
 Run cargo-vet
This checks if dependencies were audited by a "trusted party"
rust-crate-audits - collection of Google's audits
 Run cargo-crev
This is a distrubuted core-review platform
 Run cargo-deny
Cargo plugin for linting your dependencies



## Looking for vulnerabilities

The ultimate tool for detection of vulnerabilities is `cargo-audit` - you should just use it.
The [`cargo-audit` compares dependencies]() against a database with known vulnerabilities:

```bash
cargo audit
```

### Old versions

Even if a dependency doesn't have vulns, it's still worth knowing if it can be updated.

For that task you [use `cargo-outdated` tool](https://github.com/kbknapp/cargo-outdated), which lists dependencies that have newer versions available:

```bash
cargo outdated --workspace
```

{{< hint info >}}
"Removed" label in the output means that the dependency would be removed from the dependency tree if its parent was updated.
{{< /hint >}}

Another way to detect crates with newer versions [available is to use `cargo-edit`](https://github.com/killercup/cargo-edit?tab=readme-ov-file#cargo-upgrade):
```bash
cargo upgrade --incompatible --dry-run
```

### Divergent versions

It may happen that your project depends on multiple different versions of the same dependency.
While that's not necessarily a security problem, it's better to limit number of divergent versions of a crate.

To detect dependencies with multiple versions [use the `cargo-deny`](https://github.com/EmbarkStudios/cargo-deny):

```bash
cargo deny check bans --exclude-dev
```

{{< hint info >}}
Look for `warning[duplicate]` outputs.
{{< /hint >}}


Similarly, a dependency that is obtained from multiple sources (e.g., `crates.io` and `github.com`) may indicate some issues.
To report such offending dependencies use [cargo-vendor](https://doc.rust-lang.org/cargo/commands/cargo-vendor.html):

```bash
cargo vendor --locked ./tmp_path
```
