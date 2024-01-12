---
title: "Model checking"
slug: rust-advanced-testing
summary: "This section lists advanced testing tools for Rust"
weight: 20
---

# Model checking

Model checking is about verification that a program works correctly for all possible inputs.

Instead of testing with a single value (like with unit testing) or with a set of values (like with property testing)
we check all possible values - and hope that smart algorithms will make it possible to finish testing in a reasonable time.

## Prusti

[Prusti](https://github.com/viperproject/prusti-dev) is based on [Viper](https://www.pm.inf.ethz.ch/research/viper.html) - a framework for building verification tools.
It uses symbolic execution and [Z3 Theorem Prover](https://github.com/Z3Prover/z3).

### Installation

Authors recommend using [Visual Studio Code extension](https://marketplace.visualstudio.com/items?itemName=viper-admin.prusti-assistant). Command-line tools can be [downloaded from GitHub's Releases](https://github.com/viperproject/prusti-dev/releases)


### Usage

You can simply run Prusti on your code and it will look for:
* absence of reachable panics
* absence of reachable, failing assertions
* absence of integer overflows

Prusti detects all functions in a project (even unreachable ones) and checks them "independently".
It simply assumes that functions arguments can take any value - are bounded only by their types.

Please note that Prusti [does not check testing code](https://viperproject.github.io/prusti-dev/user-guide/tour/testing.html).

To restrict values, and to define more code's properties for verification, we have to
create specifications for functions.

#### Function specifications

The main power of Prusti lays in its ability to specify and validate functions' contracts (or specifications).
A function's specification consists of pre- and post-conditions.

* Pre-conditions
  * are checked *before* calls
  * Prust verifies that all calls to the function are done with arguments meeting the pre-conditions
  * Pre-condition limits set of possible values for post-condition checks
* Post-conditions
  * are checked *after* function returns
  * Prust verifies that post-conditions are meet at all exit-points of the function

In the example below, conditions are implemented with Rust attributes:
`requires` (pre-) and `ensures` (post-).

Prusti will check if all calls to `prusti_check` pass the argument that is less or equal to 20.

Then it will check if possible return values from the `prusti_check` function are below 10 - assuming
the input is less or equal to 20.

```rust
use prusti_contracts::*;
fn main() { 
    prusti_check(20);
    prusti_check(11);
}

#[requires(x <= 20)]
#[ensures(x < 10)]
fn prusti_check(x: u32) -> u32 {
    if x >= 10 {
        return x / 100;
    }
    return x;
}
```

If values violating conditions are found, Prusti retruns an error and can produce [an example set of values that demonstrate the problem](https://viperproject.github.io/prusti-dev/user-guide/verify/counterexample.html).

{{< hint danger >}}
**Prusti does not support loops automatically**

You have to specify [`body_invariant`s](https://viperproject.github.io/prusti-dev/user-guide/tour/loop_invariants.html) to enable code verification.
{{< /hint >}}


## Kani

[Kani](https://github.com/model-checking/kani) is a frontend for [CBMC](https://www.cprover.org/cbmc/) (Bounded Model Checker for C and C++).

### Installation

You can [simply use cargo for installation](https://model-checking.github.io/kani/install-guide.html).

```sh
cargo install --locked kani-verifier
cargo kani setup
```

### Basic usage

Kani reasembles normal unit tests writing. You have to write a test and run 

```sh
cargo kani
```

However, instead of using concrete values, use `kani::any()` to create a "symbolic" (or unbounded or nondeterministic) variable.
Such variable can take any value (of its type).

Runnig the test, Kani will verify absence of the following conditions for all poosible values
of the symbolic variables:
* failing assertions
* panics
* memory safety issues
* integer overflows

If the code to test is too complex, Kani may take long time to finish or even not terminate at all.
To overcome this, we can use three features:

* [`kani::assume`](https://model-checking.github.io/kani/tutorial-first-steps.html#assertions-assumptions-and-harnesses) - for restricting (bounding) symbolic values. It is a bit similar to [Prusti's pre-conditions](/docs/languages/rust/rust-advanced-testing/#function-specifications)
* [`kani::unwind`](https://model-checking.github.io/kani/tutorial-loop-unwinding.html) - for controlling bounds for loops. Kani will assume that loops can loop only the configured
amount of times. Greater the amount, slower the execution. But configuring the amount to be too small, Kani will fail too early. This is the mechanism that overcomes [Prusti's limitation with the `body_invariant`](http://localhost:1313/docs/languages/rust/rust-advanced-testing/#usage). 
* [`kani::Arbitrary`](https://model-checking.github.io/kani/tutorial-nondeterministic-variables.html#custom-nondeterministic-types) - for defining per-type limitations for symbolic values


Lets see an example:

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

We define a new `verification` module under `cfg(kani)` attribute - this lets us disable Kani-specific code when
not needed. Then we implement `kani::Arbitrary` trait to tell Kani how to generate symbolic `Book`s:
by limiting set of `title`s to three possible values and using unbounded number the `pages` field.

Then we use the `#[kani::proof]` attribute and write a test similar to normal unit tests. With three main differences:
* generating symbolic `book` variable (using our `kani::Arbitrary` implementation)
* restricting `book.pages` to be less than 4096
* limiting amount of loops to 20 with `#[kani::unwind(20)]`

[Kani documenatation recommends](https://model-checking.github.io/kani/tutorial-loop-unwinding.html) to set the `kani::unwind` experimentaly:
* start with a number a bit larger than the maximum of the expected numbers of all loops' repetitions
* if Kali takes too much time to finish - lower the `unwind` number
* if Kali errors out with `FAILURE: unwinding assertion loop X` - increase the `unwind` number

If Kali found a `FAILURE`, then we can generate example values that will trigger the failure with one of two mthods:
* generating a normal unit test with `cargo kani --concrete-playback print -Z concrete-playback`
* generating a HTML report with `cargo kani --visualize --enable-unstable` 

{{< hint danger >}}
**Kali does not scale well for:**

* strings with unbounded content (i.e., long strings with arbitrary data)
* structures of symbolic sizes that involves heap allocations
{{< /hint >}}


## Other model checkers

#### [Creusot](https://github.com/xldenis/creusot)
- based on [Why3](https://why3.lri.fr/)
- allows to provide and verify functions specifications

#### [Crux](https://github.com/GaloisInc/crucible/blob/master/crux-mir/README.md)
- symbolic analysis
- enables writing "symbolized" unit tests

#### [Flux](https://github.com/flux-rs/flux)
- refinement type checker
- allows you to annotate functions with complex conditions

#### [MIRAI](https://github.com/facebookexperimental/MIRAI)
- implements abstract interpretation, taint analysis, and constant time analysis

#### [Stateright](https://www.stateright.rs/title-page.html)
- TLA+ for rust
- lets you model state machine of a system and test properties on it

## Concurrency testing

#### [`Shuttle`](https://github.com/awslabs/shuttle)
- is un-sound, but is scalable
- does random testing, analogously to the property testing

#### [`Loom`](https://docs.rs/loom/latest/loom/)
- is sound, but slow
- works analogously to model checkers
