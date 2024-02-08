---
weight: 2
bookFlatSection: true
title: "Formal verification"
---

# Formal verification

This section presents a number of tools that can be used to formally verify
cryptographic protocols. It currently covers the symbolic protocol verifier
Tamarin, but our long-term goal is to cover both symbolic and computational
verifiers. For each tool, we go though:

- Installation and basic use
- How to define and formally verify a new model
- Tool-specific pain points, and potential workarounds

{{< section >}}

## Background

Formal verification tools allow us to formally prove security properties of cryptographic protocols. Alternatively, they
can often provide counterexamples (and sometimes real attacks) showing that a particular protocol does not guarantee the
security properties that we expect it to. To formally verify a protocol we need to describe the protocol we are
reviewing in a language understood by the tool, and we also need to describe the security properties that we would like
the protocol to have. The tool will then automatically search for a formal proof that the properties we have specified
are upheld by the protocol, and if it terminates, it will output either a proof showing that the properties hold, or a
counterexample showing how some property fails to hold.

For this reason, formal verification tools provide great value for anyone designing a new cryptographic protocol. They
allow developers to verify that a new design meets the expected security guarantees. They allow us to experiment with
the design and compare the security properties and trade-offs between different design choices. Formal verification
tools also provide great value for anyone who is modifying or extending an already existing protocol. If the original
protocol already has a formal model, modeling an extension to the protocol is typically cheap, allowing the developer to
prove that the protocol extension is secure without having to model the entire protocol from scratch.

{{< hint danger >}}

### What is a cryptographic protocol?

You may think that only cryptographers design cryptographic protocols, and that you don't need complex tools to
understand the security properties of your relatively simple use case. However, our experience shows that it makes more
sense to take the following very broad view of the term _cryptographic protocol_, which also has implications for formal
verification.

**Anyone who is composing different cryptographic primitives (like encryption, signatures, and hashes) in a way that has
not been previously specified by a standards document like an IETF RFC or NIST standard, and has not been analyzed in a
public academic paper, is designing a new cryptographic protocol.**

New cryptographic protocols need to be proven secure before they are deployed. Formal verification is one way of
achieving this which ensures both correctness and auditability. At Trail of Bits, we recommend that _all_ new
cryptographic protocols should be formally verified.

{{< /hint >}}

## The symbolic model or the computational model?

Tools used to formally verify cryptographic protocols typically come in one of two different flavors. Tools like
[ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/), [Tamarin](https://tamarin-prover.com/), and
[Verifpal](https://verifpal.com/) analyze protocols in the _symbolic model_. This means that cryptographic primitives
are modeled as black boxes satisfying certain given equations. For example, symmetric encryption could be modeled using
two functions `encrypt` and `decrypt` satisfying the following equation:

```js
decrypt(key, encrypt(key, data)) = data
```

This allows the tool to replace any occurrence of the term `decrypt(key, encrypt(key, data))` with `data`, but it says
nothing about the strength of the encryption algorithm. In a sense, it treats the encryption as perfect, since the only
way to obtain the plaintext from the ciphertext is with knowledge of the correct key. Modeling cryptographic primitives
in this way implies a number of trade-offs that may not be immediately obvious. On the one hand, it provides clean
abstractions that allows us to specify the high-level building blocks of cryptographic protocols without having to worry
too much about how each cryptographic primitive is implemented. This also allows us to instantiate the protocol with any
primitive that satisfies the given equations and still be sure that the security proofs hold. On the other hand, it
means that we cannot reason about some things like brute-force or padding-oracle attacks in a straight-forward manner.
(If we want to do this, we need to model our primitives in a way that allow us to express these types of attacks within
the model. Depending on the security properties we are interested in, this may either add complexity, which often has
adverse effects on proving time, or may sometimes be impossible within the symbolic model.)

Symbolic verification tools typically model the network as untrusted, allowing the attacker to intercept, delay, modify,
and replay messages between participants at will. This is known as the _Dolev-Yao model_, and was first described in the
paper [_On the Security of Public-Key Protocols_](https://www.cs.huji.ac.il/~dolev/pubs/dolev-yao-ieee-01056650.pdf).
Individual tools often provide abstractions (like the `reliable-channel` builtin in Tamarin or the `passive` keyword in
Verifpal) that can be used to restrict the capabilities of the attacker in different ways.

Tools like [CryptoVerif](https://bblanche.gitlabpages.inria.fr/CryptoVerif/) analyze protocols in the _computational
model_. Here, individual messages are modeled as bitstrings, cryptographic primitives are modeled as functions on
bitstrings, and the adversary is modeled as an arbitrary probabilistic polynomial-time Turing Machine. The probability
of the attacker successfully breaking the security of a given primitive has to be provided up-front by the user. The
tool can then automatically prove indistinguishability between sequences of games (up to some probability), where the
first game captures the analyzed protocol, and the final game is one where the required security property is obvious.
The output is given as a bound on the probability of a successful attack as a function of the security parameters of the
individual primitives used, and the number of protocol executions. A key benefit of the computational model is that this
mimics how cryptographers usually prove security of cryptographic protocols. This makes it easier to carry over
constructions from traditional pen-and-paper proofs to automated proofs.

The computational model is clearly more expressive than the symbolic model. However, it is also presupposes a deep
understanding of provable security and game-based proofs, which is not required when working in the symbolic model.

Ultimately, which tool to use depends as much on your background as on the protocol you are trying to analyze. If you
don't have a background in cryptography or formal verification we recommend that you start out with a simple symbolic
verification tool like Verifpal. If you struggle to model your protocol in Verifpal, or need to express more complex
security properties that are not supported by the tool, we suggest switching to a more expressive and mature symbolic
prover like ProVerif or Tamarin. Finally, if you want to bound attack probabilities or translate a game-based proof from
a paper, you need to work in the computational model with a tool like CryptoVerif.

{{< hint info >}}

### Where do I start?

[Verifpal](https://verifpal.com) is a great starting point if you have no previous exposure to formal verification. It
has a small set of built-in primitives that cover a range of use-cases, and the syntax mimics how developers typically
think about cryptographic protocols. Verifpal's intuitive syntax also makes the resulting models easier to parse and
maintain for less experienced users.

This is an important point. If you develop a formal model of a protocol that is too complex for the developers of the
protocol to maintain, then the proof becomes a snapshot in time with limited usefulness. If developers understand the
model and can update and extend it as the protocol develops, it can be built on to provide assurance for future versions
of the protocol as well.

{{< /hint >}}

{{< hint info >}}

### How do I start?

Since most cryptographic protocols have a large number of valid states, formal verification tools often struggle because
of state-space explosion. For this reason, it is generally a good idea to try to divide your protocol into smaller
components, or sub-protocols, like _registering a new device_ or _sending and receiving a single message_, and try to
prove that these individual components provide the expected security guarantees.

This approach clearly limits what the attacker can do since each sub-protocol is analyzed in a vacuum. However, it makes
each model more manageable and helps avoid the issue of state-space explosion. At Trail of Bits we often use this method
to quickly model protocol components on cryptographic design reviews. It is both a useful tool to verify our
understanding of the protocol, and to identify potential weaknesses in the design.

{{< /hint >}}
