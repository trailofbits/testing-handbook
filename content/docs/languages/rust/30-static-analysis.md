---
title: "Static analysis"
slug: lang-rust-static-analysis
weight: 30
---

# Rust static analysis

Static analysis involves analyzing source code without executing it.

## Clippy

Clippy is the fundamental linter. Just use it.

[Clippy lints](https://rust-lang.github.io/rust-clippy/master/index.html) are categorized into groups and levels. Groups categorize lints by the types of issues they detect. Levels indicate what to do when a lint finds an issue:

* Allow: Ignore the issue  
* Warn: Print a message to stdout  
* Deny: Return an error code (useful in CI pipelines)

Clippy is a wrapper over the `rustc` compiler, so when Clippy is run, it executes [its own set of lints](https://doc.rust-lang.org/rustc/lints/listing/index.html) in addition to `rustc`’s. These lints are similarly categorized and can be controlled with the same flags and configuration options.

For one-off security reviews, you want to get indicators of buggy code. For that, use the default configuration. It enables all warnings and deny lints:

```sh
cargo clippy
```

For audits of very mature codebases, you want to enable more groups:

```sh
cargo clippy -- -W clippy::pedantic -W clippy::nursery
```

Finally, you can get them all (`rustc` allow lints must be enabled one by one, and some require additional features):

```sh
cargo clippy -- \
	-Zcrate-attr="feature(non_exhaustive_omitted_patterns_lint)" \
	-Zcrate-attr="feature(strict_provenance)" \
	-Zcrate-attr="feature(multiple_supertrait_upcastable)" \
	-Zcrate-attr="feature(must_not_suspend)" \
	-W $(rustc -W help | grep '  allow' | cut -w -f2 | awk 'ORS=" -W"') \
	clippy::pedantic -W clippy::nursery -W clippy::restriction -A dead_code
```

{{< hint info >}}
These are our favorite lints:
* [`arithmetic_side_effects`](https://rust-lang.github.io/rust-clippy/master/index.html#arithmetic_side_effects): Detects potential side effects of arithmetic operations (e.g., integer overflows, division by zero)
* [`string_slice`](https://rust-lang.github.io/rust-clippy/master/index.html#string_slice): Detects potential slices that do not align with Unicode codepoints
* [`must_use_candidate`](https://rust-lang.github.io/rust-clippy/master/index.html#must_use_candidate): Checks for unused `#[must_use]` candidates

```
# WARNING: The next command modifies files!
cargo clippy --fix --allow-dirty -- -W clippy::must-use-candidate
cargo check --all-targets
```
{{< /hint >}}


If Clippy produces a lot of results, you may want to output findings in SARIF format and use [SARIF Explorer](https://github.com/trailofbits/vscode-sarif-explorer) to review them in a code editor. Use the third-party [`clippy-sarif`](https://crates.io/crates/clippy-sarif) tool for the task:  
 
```sh
cargo clippy --message-format=json | clippy-sarif
```

For continuous use, such as in a CI/CD pipeline, you want to minimize false positives and focus on the important lints. For that, follow these guidelines:

* Use the default Clippy configuration.  
* Enable recommended `clippy::restriction` lints (see the example below).  
* Enable selected lints from `clippy::pedantic` groups (these should be enabled case by case depending on your project).  
* Turn warnings into errors so that CI/CD fails on any issue.  
* Add `#[allow(..)]` attributes in the code to silence specific findings of enabled lints when really needed. Make sure to comment why the lint was disabled in the specific location.

```sh
cargo clippy -- \
	-Dwarnings -A clippy::style -W clippy::arithmetic-side-effects \
	-W clippy::string_slice -W clippy::infinite_loop \
	-W clippy::float_cmp_const
	# then enable style and pedantic like -W clippy::same-item-push -W clippy::cast_lossless
```

You can contribute new lints to Clippy. To do so, [follow the official guidance](https://doc.rust-lang.org/clippy/development/index.html).

{{< hint info >}}
To stop Clippy from producing warnings for tests, use the following configuration (e.g., in the `clippy.toml` file):

```toml
allow-expect-in-tests = true
allow-panic-in-tests = true
allow-unwrap-in-tests = true
```
{{< /hint >}}


## Dylint

[Dylint](https://github.com/trailofbits/dylint) runs lints from dynamic libraries named by the user, allowing developers to maintain their own personal lint collections. While you could write new Clippy lints and send a pull request, this is not always an ideal solution:

* The new lints cannot be project-specific.  
* The new lints cannot target third-party crates.  
* Complex lints may not be wanted due to maintenance effort.  
* Lints with a high false-positive rate may not be wanted.

Moreover, using Dylint over Clippy [helps for dealing with the unstable `rustc` API and for sharing lints with other people](https://blog.trailofbits.com/2021/11/09/write-rust-lints-without-forking-clippy/).

{{< resourceFigure "30-dylint.svg" "Clippy vs Dylint linking" >}}
Slide from "Linting with Dylint" EuroRust 2024 talk.
{{< /resourceFigure >}}

### Quick start

Install the tool:

```sh
cargo install cargo-dylint dylint-link
```

Run with lints provided by Trail of Bits:

```sh
cargo dylint --no-deps \
	--git https://github.com/trailofbits/dylint \
	--pattern examples/general cargo dylint --no-deps \
	--git https://github.com/trailofbits/dylint \
	--pattern examples/supplementary \
	-- --message-format=json | clippy-sarif > dylint.sarif
```

### Write your own lint

You can write your own lint, but it is a nontrivial task and is beyond the scope of this chapter. At a high level, you will need to decide on the type of lint:

* Pre-expansion: Run on the AST before macros are expanded  
* Early: Run on the AST after macros have been expanded  
* Late: Run on the high-level intermediate representation (HIR)—that is, after names have been resolved, types have been checked, etc.

Check out [Samuel Moelius’s ‘Linting with Dylint’ EuroRust 2024](https://youtu.be/MjlPUA7sAmA?t=548) talk' for detailed guidelines

## Other tools

### Semgrep

Semgrep has support for the Rust language. Check the [Semgrep page](/docs/static-analysis/semgrep/) in the handbook for more information on the tool.

```rust
semgrep --config "p/rust"
```

### no-panic

The [`dtolnay/no-panic` macro](https://github.com/dtolnay/no-panic) can be used to prove the absence of panics in given functions, using the compiler as the analysis engine.