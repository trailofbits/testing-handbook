---
title: "Rule-based models"
slug: rule-based-models
summary: "This section describes how to define a Tamarin model using multiset rewrite rules."
weight: 10
---

# Rule-based models

A Tamarin model can be defined either using multiset rewrite rules, or as processes using Sapic+. This section will
introduce the rewrite rule-based approach.

## Execution traces

In Tamarin, the execution state of a protocol is given by a multiset of facts. We execute the protocol by applying
rewrite rules to the state, which remove some facts and add others to the state. A single execution of the
protocol, starting from an empty state, is called an _execution trace_.

## Defining rewrite rules

Rewrite rules are defined using the following syntax:

```ml
rule Rule_name:
  [ input facts ] --[ action facts ]-> [ output facts ]
```

This should be interpreted as follows: if we have the given input facts, we can execute the rule to emit the action
facts and produce the corresponding output facts. By default, the input facts are replaced by the output fact in the
global state. _Action facts_ can be thought of as signals, indicating that some event has occurred, or that a term
satisfies a certain property. They can be referenced by lemmas and are useful for describing protocol properties that do
not directly reference the execution state. Some rules don't have action facts. In this case, we can abbreviate the rule
definition using the following shorter syntax.

```ml
rule Rule_name:
  [ input facts ] --> [ output facts ]
```

It is also possible to include definitions using `let` statements to make rules more readable:

```ml
rule Rule_name:
  let
    x = f(a, b, ...)
    y = g(a, b, ...)
  in
    [ input facts containing a, b, ... ] --> [ output facts containing x, y, a, b, ... ]
```

## Linear and persistent facts

By default, Tamarin rules consume the set of input facts when they are executed. This means that if the global state is
given by `{DeviceState(~x, pk(~x)), F(~y)}` and we execute the following rule, then `Fr(~y)` would be consumed and the
updated global state would be given by `{DeviceState(~x, pk(~x)), DeviceState(~y, pk(~y))}`.

```ml
rule Initialize_device:
  let
    public_key = pk(~private_key)
  in
    [ Fr(~private_key) ] --> [ DeviceState(~private_key, public_key) ]
```

Consuming `Fr(~y)` here ensures that the random value `~y` is not reused which would risk breaking the security
guarantees of the scheme. However, facts like `DeviceState(~y, pk(~y))`, which represents an initialized device, should
probably be reusable multiple times. For example, we may have a rule which signs a message using the private key `~y`
that we want to be able to execute multiple times.

We can indicate to Tamarin that `DeviceState(~y, pk(~y))` is a _persistent fact_ and is not consumed when it is used
as input to a rule, by prefixing the name with an exclamation mark `!`. (Note that the exclamation mark must be used
wherever `DeviceState` is used to signal that `DeviceState` is a persistent fact.) Ordinary facts, that are consumed
when used, are called _linear facts_.

## Modeling local state

Linear facts can be used to model the current state of protocol participants. As an example, consider the following
protocol between Alice and Bob.

{{< mermaid >}}
sequenceDiagram
    Alice ->> Bob: e
    Bob ->> Alice: e, ee, s, es
    Alice ->> Bob: s, se
{{< /mermaid >}}

The diagram is a high-level description of the Noise XX handshake between Alice and Bob. We don't need to worry about
the content of the individual messages sent. However, it is clear that Alice and Bob have to track their local state
to be able to progress and complete the handshake since Alice's message in step 3 of the protocol depends on what she
sent to Bob in step 1. Linear facts are useful when modeling this type of linear progression through a protocol. We can
denote Alice's local state after step 1 by `Alice_1(...)`, and have the rule modeling step 1 output Alice's local state.

```ml
rule Noise_XX_1:
  [ ... ]
  -->
  [
    Alice_1(...),
    Out(...)
  ]
```

In step 3, when Alice responds to Bob's message to complete the handshake, the local state `Alice_1(...)` is consumed.
This ensures that the attacker cannot rewind the protocol and complete the handshake multiple times from `Alice_1(...)`.

```ml
rule Noise_XX_3:
  [
    Alice_1(...),
    In(...)
  ]
  -->
  [
    Out(...)
  ]
```

## Where do facts come from?

Most rules take some facts as input and produce new facts as output. A natural question is, how do we get started? For
example, if each execution trace starts from the empty state, how would we ever be able to execute the
`Initialize_device` rule defined above? The answer is that Tamarin has a built-in rule to generate fresh values. In
fact, `Fr(...)` may only occur as input in user-defined rules to ensure that the corresponding value is unique.
