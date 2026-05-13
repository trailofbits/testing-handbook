---
title: "Specialized testing"
slug: lang-rust-specialized-testing
weight: 70
---

# Rust specialized testing

## Concurrency testing

[Shuttle](https://github.com/awslabs/shuttle)

* Unsound, but scalable  
* Works analogously to property testing

[Loom](https://docs.rs/loom/latest/loom/)

* Sound, but slow  
* Works analogously to model checkers

## Fault injection

[MadSim](https://github.com/madsim-rs/madsim)

* Replaces the `tokio` and `tonic` crates with simulated versions  
* Injects faults and increases randomness

[fail-rs](https://github.com/tikv/fail-rs)

* Needs you to manually add `fail_point!` macros into the code
