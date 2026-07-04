---
title: "Model checking"
slug: model-checking
weight: 60
---

# Rust model checking

Model checking means verifying that a program works correctly for all possible inputs.

Instead of testing with a single value (like with unit testing) or with a set of values (like with property testing), we check all possible values—and hope that smart algorithms will make it possible to finish testing in a reasonable time.

## Prusti

[Prusti](https://github.com/viperproject/prusti-dev) is based on [Viper](https://www.pm.inf.ethz.ch/research/viper.html), a framework for building verification tools. It uses symbolic execution and the [Z3 theorem prover](https://github.com/Z3Prover/z3).

{{< hint warning >}}
It is an academic project that seems to be stale. However, it can be used to experiment with this type of testing. For production uses consider other tools like Kani or Verus.
{{< /hint >}}

### Installing Prusti

The developers recommend using the [Visual Studio Code extension](https://marketplace.visualstudio.com/items?itemName=viper-admin.prusti-assistant). Command-line tools can be [downloaded from the Prusti GitHub’s releases page](https://github.com/viperproject/prusti-dev/releases).

### Usage

You can simply run Prusti on your code and it will look for the following:

* Absence of reachable panics
* Absence of reachable, failing assertions
* Absence of integer overflows

Prusti detects all functions in a project (even unreachable ones) and checks them "independently." It simply assumes that function arguments can take any value—that they are bounded only by their types.

Please note that Prusti [does not check testing code](https://viperproject.github.io/prusti-dev/user-guide/tour/testing.html).

To restrict values, and to define more code properties for verification, you have to create specifications for functions.

### Function specifications

The main power of Prusti lies in its ability to specify and validate functions’ contracts (or specifications). A function’s specification consists of preconditions and postconditions.

* Preconditions  
  * These conditions are checked before calls.
  * Prusti verifies that all calls to the function are done with arguments meeting the preconditions.
  * Preconditions limit the set of possible values for postcondition checks.
* Postconditions
  * These conditions are checked after function returns.
  * Prusti verifies that postconditions are met at all exit points of the function.

In the example below, conditions are implemented with Rust attributes: `requires` (preconditions) and `ensures` (postconditions). Prusti will check if all calls to `prusti_check` pass the argument that is less than or equal to 20. Then it will check if possible return values from the `prusti_check` function are below 10, assuming the input is less than or equal to 20.

```rust
use prusti_contracts::*;
fn main() {
    prusti_check(20);
    prusti_check(11);
}

#[requires(x <= 20)]
#[ensures(result < 10)]
fn prusti_check(x: u32) -> u32 {
    if x >= 10 {
        return x / 100;
    }
    return x;
}
```

If values violating conditions are found, Prusti returns an error and can produce [an example set of values that demonstrate the problem](https://viperproject.github.io/prusti-dev/user-guide/verify/counterexample.html).

{{< hint danger >}}
Prusti does not support loops automatically. You have to use [`body_invariant!`](https://viperproject.github.io/prusti-dev/user-guide/tour/loop_invariants.html) macro to enable code verification.
{{< /hint >}}

## Kani

[Kani](https://github.com/model-checking/kani) is a frontend for [CBMC](https://www.cprover.org/cbmc/) (Bounded Model Checker for C and C++).

### Installing Kani

You can simply [use Cargo to install it](https://model-checking.github.io/kani/install-guide.html).

```sh
cargo install --locked kani-verifier
cargo kani setup
```

### Basic usage

Using Kani is similar to writing normal unit tests. You first write a test and then run this command:

```sh
cargo kani
```

However, instead of using concrete values, use `kani::any()` to create a "symbolic" (or unbounded or nondeterministic) variable. Such variables can take any value (of their type).

Running the test, Kani will verify the absence of the following conditions for all possible values of the symbolic variables:

* Failing assertions
* Panics
* Memory safety issues
* Integer overflows

If the code to test is too complex, Kani may take a long time to finish or may not even terminate at all. To overcome this, you can use three features:

* [`kani::assume`](https://model-checking.github.io/kani/tutorial-first-steps.html#assertions-assumptions-and-harnesses): For restricting (bounding) symbolic values. It is a bit similar to [Prusti’s preconditions](#function-specifications).
* [`kani::unwind`](https://model-checking.github.io/kani/tutorial-loop-unwinding.html): For controlling bounds for loops. Kani will assume that loops can loop only the configured number of times. The greater the number, the slower the execution. But if the number is configured to be too small, Kani will report an unwinding-assertion failure (`FAILURE: unwinding assertion loop <N>`). This is the mechanism that overcomes Prusti’s limitation with the `body_invariant!` macro.
* [`kani::Arbitrary`](https://model-checking.github.io/kani/tutorial-nondeterministic-variables.html#custom-nondeterministic-types): For defining per-type limitations for symbolic values.

Let’s see an example:

```rust
pub struct Book {
    title: String,
    pages: u16
}

fn read_book(r: Book) -> u16 {
    return if r.title == "The Black Book" {
        0
    } else {
        let mut letters = 0;
        for page in 0..r.pages {
            if page == 13 {
                panic!("Bad luck");
            }
            letters += page;
        }
        letters
    }
}

#[cfg(kani)]
mod verification {
    use crate::{Book, read_book};

    impl kani::Arbitrary for Book {
        fn any() -> Self {
            let titles = vec!["The Black Book", "Lord of the ToB",
                              "The White Book"];
            let title_id: usize = kani::any();
            kani::assume(title_id < titles.len());
            Book { title: titles[title_id].to_string(), pages: kani::any() }
        }
    }

    #[kani::proof]
    #[kani::unwind(18)]
    fn verify_book() {
        let book: Book = kani::any();
        kani::assume(book.pages < 4096);
        let y = read_book(book);
        assert!(y < 100);
    }
}
```

Here we have a simple structure and a function that panics for some inputs.

We define a new `verification` module under the `#[cfg(kani)]` attribute. This lets us disable Kani-specific code when not needed. Then, we implement the `kani::Arbitrary` trait to tell Kani how to generate symbolic `Books`: by limiting the set of `titles` to three possible values and using unbounded numbers in the `pages` field.

Then, we use the `#[kani::proof]` attribute and write a test similar to normal unit tests, with three main differences:

* Generating a symbolic `book` variable (using our `kani::Arbitrary` implementation)  
* Restricting `book.pages` to be less than 4096  
* Limiting the number of loops to 18 with `#[kani::unwind(18)]`

The [Kani documentation recommends](https://model-checking.github.io/kani/tutorial-loop-unwinding.html) setting the `#[kani::unwind(X)]` attribute experimentally:

* Start with a number that is slightly larger than the maximum of the expected numbers of all loops’ repetitions.  
* If Kani takes too much time to finish, lower the `unwind` number.  
* If Kani errors out with `FAILURE: unwinding assertion loop X`, increase the unwind number.

If Kani finds a `FAILURE`, then we can generate example values that will trigger the failure with one of two methods:

* Printing a unit test that reproduces the failure with `cargo kani -Z concrete-playback --concrete-playback=print`  
* [Writing that unit test directly into your source](https://model-checking.github.io/kani/reference/experimental/concrete-playback.html) with `cargo kani -Z concrete-playback --concrete-playback=inplace`, then replaying it via `cargo kani playback -Z concrete-playback -- <test_name>`

{{< hint danger >}}
Kani does not scale well for the following:

* Strings with unbounded content (i.e., long strings with arbitrary data)
* Structures of symbolic sizes that involve heap allocations.
{{< /hint >}}

## Other model checkers

[Creusot](https://github.com/creusot-rs/creusot)

* Based on [Why3](https://www.why3.org/)
* Allows you to provide and verify function specifications

[Crux-mir](https://github.com/GaloisInc/crucible/tree/master/crux-mir)

* Symbolic analysis
* Enables writing of "symbolized" unit tests

[Flux](https://github.com/flux-rs/flux)

* Refinement type checker
* Allows you to annotate functions with complex conditions

[Verus](https://github.com/verus-lang/verus)

* SMT-based
* Lets you add `requires`/`ensures` clauses to functions

[Aeneas](https://github.com/AeneasVerif/aeneas)

* Converts Rust code to pure lambda calculus (LEAN, Coq, etc.)

[MIRAI](https://github.com/endorlabs/MIRAI)

* Implements abstract interpretation, taint analysis, and constant time analysis

[Stateright](https://www.stateright.rs/title-page.html)

* TLA+ for Rust
* Lets you model the state machine of a system and test properties on it
