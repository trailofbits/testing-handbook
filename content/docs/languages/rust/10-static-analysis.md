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
cargo clippy
```

Being pedantic won't hurt.
```sh
cargo clippy -- -W clippy::pedantic
```

A nice list of lints can be found at [rust-lang.github.io](https://rust-lang.github.io/rust-clippy/master/index.html).

## Dylint

Clippy is nice, but [creating custom lints](https://doc.rust-lang.org/nightly/clippy/development/adding_lints.html) is [a bit of a pain](https://blog.trailofbits.com/2021/11/09/write-rust-lints-without-forking-clippy/).

To write your own lints and to take adventage of not-standarized lints of others people [use `dylint`](https://github.com/trailofbits/dylint/) - dynamic linter.

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

TODO!

```sh
cargo dylint --new <path>
```

Now implement the `LateLintPass` trait and accommodate the symbols asking to be filled in.


## Prusti

* based on [Viper](https://www.pm.inf.ethz.ch/research/viper.html)
* detects panics and integer overflows

## Semgrep

Check the [semgrep page](/docs/static-analysis/semgrep/).
