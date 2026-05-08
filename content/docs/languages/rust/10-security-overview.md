---
title: "Security overview"
slug: lang-rust-security-overview
weight: 10
---

# Rust security overview

## Safety and security

The Rust compiler guarantees the memory safety of Rust programs: no undefined behavior or data race will happen during runtime, no matter the inputs.

Therefore, when security-testing Rust programs, it’s important to understand what is and what is not considered undefined behavior (UB). There is no sense in looking for double-free bugs in (safe) Rust, right? For the guarantees made by the Rust compiler, see the ["Behavior considered undefined"](https://doc.rust-lang.org/reference/behavior-considered-undefined.html) Rust Reference page.

Another important Rust concept is [*safety*](https://doc.rust-lang.org/nomicon/safe-unsafe-meaning.html). A code is marked `unsafe` when it requires special scrutiny: it may produce undefined behavior if written poorly, and it is the developer’s responsibility (not the compiler’s) to ensure the code upholds some specific contract.

{{< mermaid >}}
flowchart LR
    subgraph Input[" "]
        direction TB
        A[Safe Rust]
        C[Unsafe Rust]
    end
    A --> B[Is Sound]
    C --> D{Sound?}
    D -->|Yes| B
    D -->|No| E[Not Sound]
    B --> F[No Undefined Behavior]
    E --> G[UB Possible]
    F --> H[Vulnerabilities Possible]
    G --> H

    style Input fill:none,stroke:none
    style A fill:#000,color:#fff,stroke:#000
    style B fill:#000,color:#fff,stroke:#000
    style C fill:#ad182b,color:#fff,stroke:#ad182b
    style D fill:#ad182b,color:#fff,stroke:#ad182b
    style E fill:#ad182b,color:#fff,stroke:#ad182b
    style F fill:#000,color:#fff,stroke:#000
    style G fill:#ad182b,color:#fff,stroke:#ad182b
    style H fill:#ad182b,color:#fff,stroke:#ad182b
{{< /mermaid >}}

Security testing would need to ensure that any `unsafe` code is [*sound*](https://docs.rs/dtolnay/0.0.7/dtolnay/macro._03__soundness_bugs.html#soundness). In a basic audit, one would check a weaker property: that the actually implemented uses of `unsafe` code do not produce undefined behavior. But advanced testing would ensure soundness: no possible safe caller can use the `unsafe` code to produce UB. In fact, unsound code is quite a common source of vulnerabilities: code that worked correctly for a long time until a specific input triggered the bug.

Note that detecting unsafe code in Rust is easy, which greatly reduces the security testing effort. On the other hand, some unsafe code may be “hidden” in (transitive) dependencies, which is worth keeping in mind during audits.

There’s more. Some safe (defined) behavior may result in vulnerabilities. The ["Behavior not considered unsafe"](https://doc.rust-lang.org/reference/behavior-not-considered-unsafe.html) list points to notable safe behaviors that are a common source of security bugs:

* [General race conditions](https://doc.rust-lang.org/nomicon/races.html)
	* Deadlocks (blocking bugs)
	* Incorrect state synchronization (non-blocking bugs)  
* Resource leaks  
* Pointer exposures  
* Arithmetic errors  
* Nondeterminism  
* Logic errors

Moreover, safe Rust may happen to be unsound in some rare cases. Check [the issues on the Rust GitHub](https://github.com/rust-lang/rust/issues?q=is%3Aissue%20state%3Aopen%20label%3AI-unsound) and the ["Counterexamples in Type Systems"](https://counterexamples.org/intro.html) resource for more information. Usually auditors don’t need to focus on these edge cases.

## Resource leaks

Although Rust's memory safety guarantees make it difficult to accidentally create memory leaks, they don’t make it impossible (according to the [Rust documentation](https://doc.rust-lang.org/book/ch15-06-reference-cycles.html)). In the worst case, a memory leak could enable a denial-of-service attack—bad, but not terrible.

Similarly, safe Rust is allowed to leak other resources like file descriptors, shared memory, database connections, and zombie threads.

Rust is also allowed to exit without calling destructors. This may be problematic when your program does an HTTP call, destroys a secret, or closes a database connection in a destructor, for example.

## Pointer exposure

Pointer exposure is a rare but interesting class of bug where [a pointer to process memory is leaked](https://codeandbitters.com/main-as-usize/). An attacker would use such data to defeat the operating system’s address space layout randomization (ASLR). This would help with low-level exploitation (of a memory corruption bug, if the attacker were able to find one).

Pointer exposure is considered safe, because it does not make your program exploitable or behave strangely. However, you should avoid such unnecessary data exposures just in case.

## Arithmetic errors

Dealing with numbers is safe in Rust, but some operations may produce unexpected results. There are three main sources of bugs:

* [Integer overflows](https://doc.rust-lang.org/reference/expressions/operator-expr.html#overflow)  
* [Imprecision of float operations](https://seclists.org/oss-sec/2023/q2/99)  
* [Rounding errors](https://github.com/crytic/roundme)

There are [three types of integer bugs](https://phrack.org/issues/60/10.html#article): arithmetic overflows, widthness overflows, and signedness related.

Rust can handle arithmetic overflows in a few ways: [wrap over](https://doc.rust-lang.org/std/intrinsics/fn.wrapping_add.html), [wrap with information](https://doc.rust-lang.org/std/intrinsics/fn.add_with_overflow.html), [check](https://doc.rust-lang.org/std/primitive.i32.html#method.checked_add), [saturate](https://doc.rust-lang.org/std/intrinsics/fn.saturating_add.html), [produce undefined behavior](https://doc.rust-lang.org/std/intrinsics/fn.unchecked_add.html), and panic.

| Example                  | Result    | Description                            |
|--------------------------|-----------|----------------------------------------|
| 255u8.wrapping_add(1)    | 0         | Silently wraps around to zero          |
| 255u8.overflowing_add(1) | (0, true) | Wraps and returns overflow flag        |
| 255u8.checked_add(1)     | None      | Returns Option, None on overflow       |
| 255u8.saturating_add(1)  | 255       | Clamps at max value                    |
| 255u8.unchecked_add(1)   | UB        | Unsafe, undefined behavior on overflow |
| 255u8 + 1 (debug)        | panic     | Default behavior in debug builds       |
| 255u8 + 1 (release)      | 0         | Silently wraps in release builds       |

The default behavior is to wrap over, except in debug builds, where the default is to panic. The most common assumption auditors make when reviewing Rust programs is that overflows should not happen and any integer overflow is a potential bug. If you want to make auditors' lives easier, then be explicit about arithmetic that is expected to wrap over or saturate.

You can read more about integer overflows in [RFC 560](https://github.com/rust-lang/rfcs/blob/ae1394021c001cae2bcdfe3d7f3098dc9e3fbd27/text/0560-integer-overflow.md) and the blog post ["Myths and Legends about Integer Overflow in Rust"](https://huonw.github.io/blog/2016/04/myths-and-legends-about-integer-overflow-in-rust/).

Widthness and signedness overflows can occur when converting between numeric types. Thanks to Rust’s lack of implicit conversions, unexpected overflows are easy to deal with, using one of the following:

* A [checked conversion](https://doc.rust-lang.org/std/convert/trait.TryFrom.html) with overflows handled explicitly (e.g., with a panic)  
* An [`as` cast](https://doc.rust-lang.org/rust-by-example/types/cast.html) that may result in a wrap-over (but is always well defined, [unlike in C](https://stackoverflow.com/questions/16188263/is-signed-integer-overflow-still-undefined-behavior-in-c))

The latter cast method is more error-prone and should get the same amount of scrutiny as arithmetic overflows. An [`as` cast](https://doc.rust-lang.org/rust-by-example/types/cast.html) silently truncates bigger integer types converted to smaller integer types, even in debug mode. 

## Nondeterminism

A Rust program that behaves differently when compiled or executed multiple times may be problematic for some kinds of systems—for example, when the program is expected to be interoperable between machines with different CPU architectures, or when data is computed and synchronized between machines as in the case of blockchain nodes.

There are two types of nondeterminism in Rust: introduced during compilation and during runtime.

The following are sources of compilation-time nondeterminism:

* Architecture-dependent integral types (like `usize` and `libc::c_char`) and pointer sizes  
* [Float numbers](https://internals.rust-lang.org/t/pre-rfc-dealing-with-broken-floating-point/2673)  
* [NaN bit representation](https://github.com/rust-lang/rfcs/blob/master/text/3514-float-semantics.md)  
* Struct field reordering  
* Enum discriminant values

The following are sources of runtime nondeterminism:

* Iterations over [`HashMap`](https://dev.to/gnunicorn/hunting-down-a-non-determinism-bug-in-our-rust-wasm-build-4fk1) and `HashSet`  
* Struct padding  
* Pointers (specific memory addresses)

## Logic errors

Logic errors are a very wide topic covering areas like [traits’ logic constraints](https://doc.rust-lang.org/reference/behavior-not-considered-unsafe.html#logic-errors), weak authentication, broken cryptography, insufficient data validation, [infinite recursion](https://blog.trailofbits.com/2025/02/21/dont-recurse-on-untrusted-input/), [operating system–level TOCTOU bugs](https://blog.trailofbits.com/2020/08/12/sinter-new-user-mode-security-enforcement-for-macos/#:~:text=2.%20Mitigating%20the%20TOCTOU%20risks%20in%20real%2Dtime%20security%20decisions), error handling, unhandled [panics](https://blog.cloudflare.com/18-november-2025-outage/), and secrets exposure.

An interesting class of logic bugs in Rust is related to ["unwind safety"](https://doc.rust-lang.org/std/panic/trait.UnwindSafe.html#what-is-unwind-safety). A thread that panics when some data is in an invalid state may allow other threads (or the same if the `catch_unwind` mechanism is used) to observe the invalid state. This may break some logic invariants or be the cause of memory corruption (in the presence of unsafe code). If the whole program is not completely killed in the event of a panic, then reviewing for this type of safety is required.
