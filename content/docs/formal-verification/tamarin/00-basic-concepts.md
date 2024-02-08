---
title: "Basic concepts"
slug: basic-concepts
summary: "This section explains the basic concepts of Tamarin."
weight: 1
---

# Installation and basic concepts

## Installing Tamarin

We recommend installing Tamarin using a package manager to ensure that the correct dependencies are installed together
with the tool. Tamarin is currently packaged for Homebrew, Arch Linux, Nixpkgs, and NixOS.

{{< tabs "installing-tamarin" >}}

{{< tab "Using Homebrew" >}}
On MacOS and Linux, you can install Tamarin using Homebrew as follows:

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

Tamarin models can be specified either using [multiset](https://en.wikipedia.org/wiki/Multiset) rewrite rules, or using
a process calculus based on a variant of the applied pi-calculus. The global protocol state is given by a multiset of
facts that is expanded and updated as the protocol progresses. Here, a fact is essentially a statement about a set of
terms. For example, _`Alice` has registered the public key `pk` with the server_, or _The attacker has learned the
private key `sk`_. Protocol properties are expressed as properties of the set of possible executions of the protocol,
and are specified using a decidable fragment of temporal logic. (This means that we can express properties of terms at
different points in time.)

### Variables and sorts

Variables in Tamarin range over five different sorts (or types). There is a top sort for messages that can be sent over
the network, with subsorts for public values, fresh (or private) values, and natural numbers. There is also a sort for
temporal values (essentially, points in time). To make the sort clear from context, each sort is prefixed by a single
character.

- `~x` denotes a fresh value. _Fresh values_ are random values like secret keys
  and nonces and are not known to the attacker.
- `$x` denotes a public value. _Public values_ are publicly known. In
  particular, they are known to the attacker. Constant public values are
  written as strings (without the `$`). For example, the constant 0x30 is
  written `'0x30'`, and a constant generator _g_ of a cyclic group is written
  `'g'`. (For example, the public key corresponding to the private key `~x` in
  a Diffie-Hellman based protocol is written `'g'^~x`.)
- `%n` denotes a natural number. _Natural numbers_ start at `%1` in Tamarin and
  require the `natural-numbers` builtin to use. They are used to represent
  (small) numbers like counters, and are assumed to be known to the attacker.
- `#i` denotes a temporal value. _Temporal values_ are not used to describe the
  protocol directly, but are used to express protocol properties like "If the
  attacker knows Alice's key at time `#j`, then Alice's key must have been
  leaked at some time `#i` before `#j`."

Terms may be composed using functions. These are either user defined, or defined by importing a predefined theory (known as a `builtin`).

{{< hint info >}}

<!-- markdownlint-disable-next-line no-emphasis-as-heading -->
**Use descriptive variable and function names**

Avoid using one-letter names for user-defined variables and functions. If you are modeling an existing protocol, reuse
names from the specification and include clear references to the section of the specification where they are defined.

{{< /hint >}}

### Functions and equations

User-defined functions are declared using the `functions` keyword. New functions can be defined in two different ways.
It is possible to define new functions by simply specifying the function name and arity (how many arguments it takes) as
follows:

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

Here, `SecretKey` and `Bytes` are arbitrary type names specified by the user.  There are a number of benefits to using
explicit types in this way when defining your own functions. Apart from making definitions more readable, all equations
are type checked by Tamarin before the prover runs. This ensures that any issues due to inconsistent typing of arguments
is caught early in the modeling process.  For example, using the term `encrypt(key, message)` in one location would
cause Tamarin to infer that `key` has type `SecretKey` and `message` has type `Bytes`.  If we later introduced the term
`decrypt(message, key)` Tamarin would complain, saying that it expected the first argument to `decrypt` to have the type
`SecretKey`, but that `message` must be of type `Bytes`. Note that function types are ignored after the type-checking
phase is complete. In particular, they do not affect how the attacker may use the defined function.

{{< hint info >}}

<!-- markdownlint-disable-next-line no-emphasis-as-heading -->
**Include function signatures with descriptive type names when declaring new functions**

We recommend always including the full function signature when introducing new functions. This makes function
definitions easier to parse, allows you to take full advantage of Tamarin's build-in typing checking, and avoid
potential typing inconsistencies.

{{< /hint >}}

To define equations that the introduced function symbols satisfy, we use the `equations` keyword. For example, we could
express that decryption is the (left-)inverse of encryption as follows:

```js
equations:
  decrypt(key, encrypt(key, data)) = data,
  ...
```

### Built-in theories

Tamarin comes with a number of cryptographic primitives such as symmetric and asymmetric encryption, signatures, and
hash functions already built-in. These built-in theories can be added to your project using the `builtins` keyword. For
example, the following would add two function symbols `senc` and `sdec` modeling symmetric encryption, and a function
symbol `h` modeling a hash function, to your project:

```js
builtins:
  symmetric-encryption,
  hashing,
  ...
```

For a complete list of the built-in theories supported by Tamarin, we refer to [the section on cryptographic messages in
the Tamarin user manual](https://tamarin-prover.com/manual/master/book/004_cryptographic-messages.html).

### Facts

Facts express properties about the current state of the protocol. New facts can be introduced by the user, but there are
a few predefined facts that are useful to know about.

- `Fr(x)` says that `x` is a fresh value. That is, a random value which cannot
  be inferred by the attacker.
- `Out('c', x)` says that `x` is sent on the public channel with name `'c'`.
  Since we're assuming a Dolev-Yao adversary who is in complete control of the
  network, this also means that `x` becomes available to the attacker as soon as
  it is sent over the network. If there is only one channel, the channel
  identifier `'c'` may be omitted.
- `In('c', x)` says that `x` is received on the public channel `'c'`.  Since the
  attacker controls the network she may drop or alter messages at will. This
  means that we cannot assume that the message `x` is ever received just
  because it is sent at some point by some honest participant, or conversely,
  that `x` was sent by an honest participant, just because `x` was received. If
  there is only one channel, the channel identifier `'c'` may be omitted.
- `K(x)` says that the attacker knows the value `x`.
- `T` and `F` denote the boolean constants `true` and `false`. They are
  sometimes useful when formulating security properties. (See below for an
  example.)

## Protocol properties and lemmas

Protocol properties are expressed as _lemmas_ in Tamarin. (In mathematics, a lemma is an intermediate step or
proposition, typically used as a stepping stone in the proof of some other theorem.) Lemmas express properties of
protocol execution traces, and by default, they contain an implicit quantification over all execution traces. For
example, consider the following lemma, which informally says that the only way that the attacker could learn the private
key of an initialized device, is if that private key is leaked to the attacker.

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

There is a lot going on here. Following the `lemma` keyword is a name which identifies the lemma. This should be
something expressive, describing the intended meaning of the statement. The `All` and `Ex` keywords represent universal
and existential quantification. The operators `&` and `==>` represent conjunction and implication. (Disjunction is
written `|`, and negation of `P` is written `not(P)`). The variables `#i`, `#j`, and `#k` all range over temporal
values. Undecorated variables like `private_key` range over messages.

The statements `DeviceInitialized(...)` and `DeviceKeyLeaked(...)` are special facts called _action facts_ in the
rewrite rule-version of Tamarin, or _events_ in the pi calculus-version. `DeviceInitialized(...) @ #i` means that the
fact occurs (that is, is added to the execution trace) at time `#i`. Facts in lemmas always have to be qualified with a
temporal variable in this way.

We note that this lemma implicitly contains a universal quantification over all execution traces of the analyzed
protocol. It is really saying that "_for any execution of the protocol_, the private key will remain confidential as
long as it is not leaked to the attacker." It is possible to make this explicit by adding the keyword `all-traces`
before the opening quotation mark. It is also possible to write lemmas that use existential quantification over
execution traces using the keyword `exists-trace`. This is useful for proving correctness properties, saying that there
exists an execution trace where the protocol completes successfully.

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

This lemma informally says that there is an execution trace where at least one device is initialized, registers its
public key with the server, without leaking the private key to the attacker. Note that the final statement, that the
device key is not leaked, is formulated in a somewhat roundabout manner. The reason for this is that lemmas must be
expressed in the _guarded fragment_ of first-order temporal logic. In practice, this means that all existentially
quantified formulas must be on the form `Ex x. (A(x, y, ..., z) @ #i & ...)` and all universally quantified formulas
must be on the form `All x. (A(x, y, ..., z) @ #i ==> ...)`. Since `not(P)` is propositionally equivalent to `P ==> F`,
the final statement allows us to express `All #k. not(DeviceKeyLeaked(public_key) @ #k)` as a guarded formula accepted
by Tamarin.

{{< hint info >}}

<!-- markdownlint-disable-next-line no-emphasis-as-heading -->
**Include a lemma ensuring that the entire protocol can be executed correctly from start to finish**

This is almost always the first lemma to prove. It may be updated as you add more components of the protocol to your
model, and serves as a form of sanity check or integration test, ensuring that the model can be executed correctly.

{{< /hint >}}

## Restricting the execution trace

Tamarin uses _restrictions_ to restrict the space of execution traces explored by the prover. The most common use case
for restrictions is to model branching behavior. Consider the following restriction which says that if the fact
`EnsureEqual(x, y)` is emitted, then `x` and `y` must evaluate to the same term.

```js
restriction ensure_equal:
  "
    All x y #i. (EnsureEqual(x, y) @ #i ==> x = y)
  "
```

This restriction defines a new fact `EnsureEqual(x, y)` that can be used to restrict execution traces to those where the
two arguments are equal. For example, we can use the fact `EnsureEqual(verify(sig, msg, pub_key), true)` to express that
the signature `sig` must be valid for the protocol to progress. For details on how restrictions are used, see the
following sections which introduce multiset rewrite rules and Sapic+.

## Rewrite rules or process calculus?

Tamarin allows the user to specify protocols using either multiset rewrite rules, or as processes using a version of the
applied pi calculus known as Sapic+. There are benefits and drawbacks of both approaches. Tamarin originally only
supported multiset rewrite rules, and if you use processes to specify your protocol, the specification will be
translated into rewrite rules before the prover runs. This means rule names will be autogenerated, and hence
unrecognizable, if you run the prover in interactive mode. Since multiset rewrite rules have been supported from the
start, there are also more examples available describing this approach. This means that if you're looking for examples
for how to model a certain protocol component, you are more likely to find examples using rewrite rules than Sapic+.

On the other hand, if you are interested in porting your model to ProVerif, Tamarin's process calculus is very similar
to the applied pi-calculus used by ProVerif. Thus, if you are already familiar with ProVerif, or if you are uncertain of
which tool would be best suited for your problem, it may make sense to use processes to model your protocol.
