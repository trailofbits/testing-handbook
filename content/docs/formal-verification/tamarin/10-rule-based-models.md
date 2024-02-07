---
title: "Rule-based models"
slug: rule-based-models
summary: "This section describes how to define a Tamarin model using multiset rewrite rules."
weight: 10
---

# Rule-based models

A Tamarin model can be defined either using multiset rewrite rules, or as
processes using Sapic+. This section will go through the rewrite rule-based
approach.

## Facts

To model a protocol using rewrite rules we view the global state of the protocol
as a multiset of _facts_. In Tamarin, a fact is a statement like "Alice has
registered the public key _Y_ with the server", or "The server successfully
decrypted the message _m_ from Bob". Rewrite rules consume facts and produce
new facts. In this way, they define a transition system which describes how the
global state is updated during the execution of the protocol. Since rules may
consume facts, the global state is modeled as a multiset which may contain
multiple instances of the same fact.

There are a few facts with predefined meanings that are useful to know about
before we start defining our own rewrite rules:

- `Fr(x)`: This says that `x` is a _fresh_ value. This means that `x` is random
  and cannot be inferred by the attacker. It also means that the value of `x`
  is unique across different runs of the protocol. Fresh values are usually used
  to model randomly generated keys, nonces, and random IVs. For convenience,
  Tamarin has a built-in rule for creating fresh values. This means that any
  rule that takes one or more fresh values as input can be executed at any time
  since new fresh values can always be created.
- `Out('c', x)`: This says that `x` is sent on the public channel with name
  `'c'`. Since we're assuming a Dolev-Yao adversary who is in complete control of
  the network, this also means that `x` becomes available to the attacker. If there
  is only one channel, the channel identifier `'c'` may be omitted.
- `In('c', x)`: This says that `x` is received on the public channel `'c'`.
  Since the attacker controls the network she may drop or alter messages at
  will. This means that we cannot assume that the message `x` is received, just
  because it is sent by some protocol participant, or conversely, that `x` was sent by some participant, just because the fact `In('c', x)` is true. If there is only one channel, the channel identifier `'c'` may be omitted.
- `K(x)`: This means that the attacker has learned `x`.

## Rewrite rules

Rewrite rules are defined using the following syntax:

```ml
rule Rule_name:
  [ input facts ] --[ action facts ]-> [ output facts ]
```
