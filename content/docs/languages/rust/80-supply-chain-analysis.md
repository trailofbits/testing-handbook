---
title: "Supply chain analysis"
slug: lang-rust-supply-chain-analysis
weight: 80
---

# Rust supply chain analysis

## Vetting

The tools in this section are more for "understanding" than "checking." That is, running them does not produce bug reports, but can help you assess the maturity and security of dependencies. The tools below are quantitative rather than qualitative; you will need to perform manual, in-depth review of the outputs to extract any solid evidence about the maturity.

### [cargo-supply-chain](https://github.com/rust-secure-code/cargo-supply-chain)

The tool reveals who you are implicitly trusting via dependencies. You want that set to be small. The tool detects both the dependencies (libraries) and authors (publishers).

```sh
$ cargo supply-chain crates

Dependency crates with the people and teams that can publish them to crates.io:

1. libc: team "github:rust-lang:libc", team "github:rust-lang:libs", someguy, someother-guy
2. unicode-bidi: team "github:servo:cargo-publish", asterix, obelix
3. bitflags: team "github:bitflags:owners", team "github:rust-lang-nursery:libs", NotMe, notY0u
```

### [cargo-vet](https://mozilla.github.io/cargo-vet/)

The tool checks if dependencies were audited by a "trusted party."

```sh
$ cargo vet

Vetting Failed!
1 unvetted dependencies:
  regex-syntax:0.8.8 missing ["safe-to-deploy"]

recommended audits for safe-to-deploy:
  Command                                  Publisher   Used By               Audit Size
  cargo vet diff regex-syntax 0.8.5 0.8.8  TheGuy  regex and regex-automata  14 files changed

```

The `cargo-vet` failure shown above means the `regex-syntax` crate is "not safe for deployment," but there is an available audit for an older version of the crate.

There are some [preconfigured auditors](https://github.com/mozilla/cargo-vet/blob/main/registry.toml), and [more can be imported](https://mozilla.github.io/cargo-vet/importing-audits.html). We recommend adding the following:

* [`rust-crate-audits`](https://github.com/google/rust-crate-audits): A collection of Google’s audits
* [`bytecodealliance/wasmtime`](https://github.com/bytecodealliance/wasmtime/blob/main/supply-chain/audits.toml)

### [cargo-crev](https://github.com/crev-dev/cargo-crev)

Yet another tool for distributed code reviews.

```sh
$ cargo crev verify --show-all

status reviews issues owner      downloads    loc lpidx geiger flgs crate   version latest_t
none     0   3  0   0  0  1 45104K 695354K   7558   115    err ____ memchr  2.7.6   ↓2.7.1
```

It cryptographically signs/verifies the audit (if that matters to you) and is more decentralized in nature than `cargo-vet`, but may require more manual configurations and cannot help with version-diff trust.

{{< hint info >}}
Use the [`crevette` tool](https://github.com/crev-dev/crevette) to convert audits from `crev` to `vet` format.
{{< /hint >}}

### [cargo-deny](https://github.com/EmbarkStudios/cargo-deny)

This plugin can be used for linting your dependencies. Use it if you want to automatically detect and warn about crates with these issues:

* Have an incompatible license
* Have multiple versions in your dependency tree
* Are explicitly banned by you
* Have public security advisories

### [cargo-unmaintained](https://github.com/trailofbits/cargo-unmaintained)

This Trail of Bits’ tool can be used in addition to `cargo audit` (see below) to detect unmaintained dependencies in a heuristic way.

### [cackle](https://github.com/cackle-rs/cackle)

The tool lists APIs (filesystem, network, environment, sockets, etc.) used by your project’s dependencies. This allows you to detect suspicious transitive dependencies that access APIs you didn’t expect them to use.


## Looking for vulnerabilities

The ultimate tool for detection of vulnerabilities is [`cargo audit`](https://crates.io/crates/cargo-audit). You should just use it. The tool compares dependencies against a database with known vulnerabilities:

```sh
$ cargo audit

   Scanning Cargo.lock for vulnerabilities (32 crate dependencies)
Crate:     h2
Version:   0.3.20
Title:     Degradation of service in h2 servers with CONTINUATION Flood
Date:      2024-04-03
ID:        RUSTSEC-2024-0332
URL:       https://rustsec.org/advisories/RUSTSEC-2024-0332
Solution:  Upgrade to ^0.3.26 OR >=0.4.4
Dependency tree:
h2 0.3.20
└── project 0.1.0
```

Even if a dependency doesn’t have vulnerabilities, it’s still worth knowing if it can be updated to a newer version. For that task, use the [`cargo outdated` tool](https://github.com/kbknapp/cargo-outdated).

```sh
$ cargo outdated --workspace

All dependencies are up to date, yay!
```

{{< hint info >}}
A "removed" label in the output means that the dependency would be removed from the dependency tree if its parent were updated.
{{< /hint >}}

Another way to detect crates with newer versions available [is to use `cargo edit`](https://github.com/killercup/cargo-edit?tab=readme-ov-file#cargo-upgrade):

```sh
cargo upgrade --incompatible --dry-run
```

## Divergent versions

It may happen that your project depends on multiple different versions of the same dependency. While that’s not necessarily a security problem, it’s better to limit the number of divergent versions of a crate.

To detect dependencies with multiple versions, use the [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny) tool.

```sh
cargo deny check bans --exclude-dev
```

{{< hint info >}}
Look for `warning[duplicate]` outputs.
{{< /hint >}}

Similarly, a dependency that is obtained from multiple sources (e.g., crates.io and github.com) may indicate some issues. To report such offending dependencies, use [`cargo vendor`](https://doc.rust-lang.org/cargo/commands/cargo-vendor.html) or `cargo-deny`'s `sources` check.

```sh
cargo vendor --locked ./tmp_path
```
Finally, to find dependencies specified in multiple `Cargo.toml` files, consider using [`cargo-autoinherit`](https://github.com/mainmatter/cargo-autoinherit).