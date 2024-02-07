---
title: "Tamarin"
weight: 2
summary: "Tamarin a a symbolic verification tool that can be used to formally
model security protocols. Protocols are described using either multiset rewrite
rules or a variant of the applied pi-calculus. Security properties are modeled using first-order temporal logic and can be proved either automatically or interactively."
bookCollapseSection: true
---

# Tamarin

Tamarin is a formal verification tool that can be used to model the security
properties of a protocol in the symbolic model. Protocols are modelled either
using multiset term rewrite rules, or using a version of the applied
pi-calculus. Security properties are specified using a fragment of first-order
temporal logic, and can be proved either automatically or interactively using a
web-based interface.

## Benefits of using Tamarin

- Built-in support for common cryptographic construction such as symmetric and
  asymmetric encryption, hashes, signatures, and Diffie-Hellman based constructions.
- Easy to define new primitives and corresponding equations.
- Security properties are specified using an expressive fragment of temporal
  first-order logic.
- Security properties can be proved either automatically or interactively.

## Ideal use case

- If you need to define custom primitives or prove more complex security properties.
  not supported by simpler tools like [Verifpal](https://verifpal.com).
- If you need to model concurrent, non-deterministic processes, which is not supported by [Verifpal](https://verifpal.com).
- If the protocol you are modeling uses multiplicative inverses to cancel out
  exponents in Diffie-Hellman based sub-protocols, or if you want to consider
  attacks based on multiplicative behavior against your protocol.
