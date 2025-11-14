---
title: "Concurrency testing"
slug: rust-concurrency-testing
summary: "This section lists advanced testing tools for Rust"
weight: 30
---

## Concurrency testing

#### [`Shuttle`](https://github.com/awslabs/shuttle)
- is un-sound, but is scalable
- does random testing, analogously to the property testing

#### [`Loom`](https://docs.rs/loom/latest/loom/)
- is sound, but slow
- works analogously to model checkers

https://github.com/BurtonQin/lockbud
