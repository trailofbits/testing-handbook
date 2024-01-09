---
title: "Static analysis"
slug: rust-static-analysis
summary: "This section provides overview of static analysis tooling for Rust"
weight: 10
---

# Static Analysis

Analyze source code without executing it.

## Clippy

Clippy is the basic linter. Just use it.

```sh
cargo clippy -- -W clippy::pedantic
```

## Dylint

To write your own lints and to take adventage of not-standarized lints of others people [use `dylint`](https://github.com/trailofbits/dylint/).

### Quick start

Add the following to `Cargo.toml`:
```toml
[workspace.metadata.dylint]
libraries = [
  { git = "https://github.com/trailofbits/dylint", pattern = "examples/general/*" },
  { git = "https://github.com/trailofbits/dylint", pattern = "examples/supplementary/*" },
]
```

And run:
```sh
cargo install cargo-dylint dylint-link
cargo dylint --all --workspace
```

### Writing your own lints

TODO

## MIRI
* detects certain classes of undefined behavior and memory leaks

## Prusti
* based on [Viper](https://www.pm.inf.ethz.ch/research/viper.html)
* detects panics and integer overflows

## Semgrep

Check the [semgrep page](/docs/static-analysis/semgrep/).
