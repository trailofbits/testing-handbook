---
title: "Property testing"
slug: rust-property-testing
summary: "This section describes nuances of Rust property testing"
weight: 20
---

# Basic property testing tools

- Use [proptest](https://docs.rs/proptest/latest/proptest/)
  - inspired by QuickCheck
  - write "randomized" unit tests
- Use [Kani](https://github.com/model-checking/kani)
  - frontend for [cbmc](https://www.cprover.org/cbmc/)
  - write "randomized" unit tests
- Use [Creusot](https://github.com/xldenis/creusot)
  - based on [Why3](https://why3.lri.fr/)
  - annotate functions with "contract expressions" (requires, ensures, invariant and variant)

# Advanced property testing tools

- Use [Crux](https://github.com/GaloisInc/crucible/blob/master/crux-mir/README.md)
  - symbolic analysis
  - write "symbolized" unit tests
- Use [Flux](https://github.com/flux-rs/flux)
  - refinement type checker
  - annotate functions with complex conditions
- Use [MIRAI](https://github.com/facebookexperimental/MIRAI)
  - implements abstract interpretation, taint analysis, and constant time analysis
  - experimantal stuff
  - requires heavy dev work to implement something usefull
- Use [Stateright](https://www.stateright.rs/title-page.html)
  - TLA+ for rust
  - lets you model state machine of a system and test properties on it
  - heavy stuff

# Concurrency testing tools

- Run [`Shuttle`](https://github.com/awslabs/shuttle)
  - randomized and lightweight testing

- Run [`Loom`](https://docs.rs/loom/latest/loom/)
  - sound but slow testing
