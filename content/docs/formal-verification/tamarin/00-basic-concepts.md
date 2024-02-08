---
title: "Installation and basic concepts"
slug: basic-concepts
summary: "This section explains the basic concepts of Tamarin."
weight: 1
---

# Installation and basic concepts

## Installing Tamarin

We recommend installing Tamarin using a package manager to ensure that the correct dependencies are installed together with the tool. Tamarin is currently packaged for Homebrew, Arch Linux, Nixpkgs, and NixOS.

{{< tabs "installing-tamarin" >}}

{{< tab "Using Homebrew" >}}
On MacOS and Linux, you can install Tamarin using Howebrew as follows:

```sh
brew install tamarin-prover/tap/tamarin-prover
```

{{< /tab >}}

{{< tab "Using Pacman" >}}
On Arch Linux you can install Tamarin using Pacman with the following command:

```sh
pacman -S tamarin-prover
```

{{< /tab >}}

{{< tab "Using the Nix package manager" >}}
You can install Tamarin from Nixpkgs using the Nix package manager with the following command:

```sh
nix-env -i tamarin-prover
```

{{< /tab >}}

{{< tab "On NixOS" >}}
If you are running NixOS you can install Tamarin by adding `tamarin-prover` to your `environment.systemPackages`.

{{< /tab >}}

{{< /tabs >}}

## Tamarin basic concepts

Tamarin models can be specified either using [multiset](https://en.wikipedia.org/wiki/Multiset) rewrite rules, or using a process calculus based on a variant of the applied pi-calculus. Protocol properties are specified using a fragment of temporal logic. This means that we can express properties of terms at given points in time. The global protocol state is given by a multiset of facts that is expanded and updated as the protocol progresses. Here, a fact is essentially a statement about a set of terms. For example, "`Alice` has registered the public key `pk` with the server", or "the attacker has learned the private key `sk`".

### Variables and sorts

Variables in Tamarin range over five different sorts (or types). There is a top sort for messages that can be sent over the network, with subsorts for public values, fresh (or private) values, and natural numbers. There is also an sort for temporal values (essentially, points in time). To make the sort clear from context, each sort is prefixed by a single character.

- `~x` denotes a fresh value. _Fresh values_ are random values like secret keys
  and nonces and are not known to the attacker.
- `$x` denotes a public value. _Public values_ are publicly known. In
  particular, they are known to the attacker. Constant public values are written as strings (without the `$`). For example, the constant 0x30 is written `'0x30'`, and a constant generator _g_ of a cyclic group is written `'g'`. (For example, the public key corresponding to the private key `~x` in a Diffie-Hellman based protocol is written `'g'^~x`.)
- `%n` denotes a natural number. _Natural numbers_ start at `%1` in Tamarin and
  require the `natural-numbers` builtin to use. They are used to represent (small) numbers like counters, and are assumed to be known to the attacker.
- `#i` denotes a temporal value. _Temporal values_ are not used to describe the
  protocol directly, but are used to express protocol properties like "If the attacker knows Alice's key at time `#j`, then Alice's key must have been leaked at some time `#i` before `#j`."

Terms may be composed using functions. These are either user defined, or defined by importing a pre-defined theory (known as a `builtin`).

### Functions and equations

User-defined functions are declared using the `functions` keyword. New functions can be defined in two different ways. It is possible to define new functions by simply specifying the function name and arity (how many arguments it takes) as follows:

```js
functions:
  encrypt/2,
  decrypt/2,
  ...
```

New functions can also be defined by specifying the full signature of the function, using user-defined type names, as follows:

```js
functions:
  encrypt(SecretKey, Bytes): Bytes,
  decrypt(SecretKey, Bytes): Bytes,
  ...
```

Here, `SecretKey` and `Bytes` are arbitrary type names specified by the user. There are a number of benefits to using explicit types in this way when defining your own functions. Apart from making definitions more readable, all equations are type checked by Tamarin before the prover runs. This ensures that any issues due to inconsistent typing of arguments is caught early in the modeling process. For example, using the term `encrypt(key, message)` in one location would cause Tamarin to infer that `key` has type `SecretKey` and `message` has type `Bytes`. If we later introduced the term `decrypt(message, key)` Tamarin would complain, saying that it expected the first argument to `decrypt` to have the type `SecretKey`, but that `message` must be of type `Bytes`. Note that function types are ignored after the type-checking phase is complete. In particular, they do not affect how the attacker may use the defined function.

{{< hint info >}}

#### Include function signatures with sensible type names when declaring new functions

We recommend always including the full function signature when introducing new functions. This makes function definitions easier to parse, allows you to take full advantage of Tamarin's build-in typing checking, and avoid potential typing inconsistencies.

{{< /hint >}}

### Facts

Facts express properties about the current state of the protocol. New facts can be introduced by the user, but there are a few pre-defined facts that are useful to know about.

- `Fr(x)` says that `x` is a fresh value. That is, a random value which cannot
  be inferred by the attacker.
- `Out('c', x)` says that `x` is sent on the public channel with name
  `'c'`. Since we're assuming a Dolev-Yao adversary who is in complete control of the network, this also means that `x` becomes available to the attacker as soon as it is sent over the network. If there is only one channel, the channel identifier `'c'` may be omitted.
- `In('c', x)` says that `x` is received on the public channel `'c'`.
  Since the attacker controls the network she may drop or alter messages at
  will. This means that we cannot assume that the message `x` is ever received just because it is sent at some point by some honest participant, or conversely, that `x` was sent by an honest participant, just because `x` was received. If there is only one channel, the channel identifier `'c'` may be omitted.
- `K(x)` says that the attacker knows the value `x`.
- `T` and `F` denote the boolean constants `true` and `false`. They are
  sometimes useful when formulating security properties. (See below for an example.)

## Protocol properties and lemmas

Protocol properties are expressed as _lemmas_ in Tamarin. (In mathematics, a lemma is an intermediate step or proposition, typically used as a stepping stone in the proof of some other theorem.) Lemmas express properties of protocol execution traces, and by default, they contain an implicit quantification over all execution traces. For example, consider the following lemma, which informally says that the only way that the attacker could learn the private key of an initialized device, is if that private key is leaked to the attacker.

```js
lemma device_key_confidentiality:
    "
      All private_key #i #j. (
        DeviceInitialized(to_public_key(private_key)) @ #i & K(private_key) @ #j
        ==>
        Ex #k. (k < j & DeviceKeyLeaked(to_public_key(private_key)) @ #k)
      )
    "
```

There is a lot going on here. Following the `lemma` keyword is a name which identifies the lemma. This should be something expressive, describing the intended meaning of the statement. The `All` and `Ex` keywords represent universal and existential quantification. The operators `&` and `==>` represent conjunction and implication. (Disjunction is written `|`, and negation is written as `not(...)`). The variables `#i`, `#j`, and `#k` all range over temporal values. Undecorated variables like `private_key` range over messages.

The statements `DeviceInitialized(...)` and `DeviceKeyLeaked(...)` are special facts called _action facts_ in the rewrite rule-version of Tamarin, or _events_ in the pi calculus-version. `DeviceInitialized(...) @ #i` means that the fact occurs (that is, is added to the execution trace) at time `#i`. Facts in lemmas always have to be qualified with a temporal variable in this way.

We note that this lemma implicitly contains a universal quantification over all execution traces of the analyzed protocol. It is really saying that "_for any execution of the protocol_, the private key will remain confidential as long as it is not leaked to the attacker." It is possible to make this explicit by adding the keyword `all-traces` before the opening quotation mark. It is also possible to write lemmas that use existential quantification over execution traces using the keyword `exists-trace`. This is useful for proving correctness properties, saying that there exists an execution trace where the protocol completes successfully.

```js
lemma protocol_correctness:
    exists-trace
    "
    Ex public_key #i #j. (
      DeviceInitialized(public_key) @ i &
      ServerInitialized(public_key) @ j &
      All #k. (DeviceKeyLeaked(public_key) @ k ==> F)
    )
    "
```

This lemma informally says that there is an execution trace where at least one device is initialized, registers its public key with the server, without leaking the private key to the attacker. Note that the final statement, that the device key is not leaked, is formulated in a somewhat roundabout fashion. The reason for this is that lemmas must be expressed in the _guarded fragment_ of first-order temporal logic. In practice, this means that all existentially quantified formulas must be on the form `Ex x. (A(x) @ #i & B(x) @ #j)` and all universally quantified formulas must be on the form `All x. (A(x) @ #i ==> B(x) @ #j)`. (Since `F` represents `false`, the guarded formula `DeviceKeyLeaked(...) @k ==> F` is equivalent to `not(DeviceKeyLeaked(...) @ k)`.)

## Restricting the execution trace

## Rewrite rules or process calculus?
