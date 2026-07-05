---
title: "Memory zeroization"
slug: memory-zeroization
weight: 50
---

# Rust memory zeroization

Zeroization in the presence of optimizing compilers is difficult. In Rust, it is particularly tricky because of the constraints the compiler imposes on memory management. The compiler can infer significant aliasing information that allows unexpected copies of secret data to appear on the stack. For example, consider the pitfall described in the blog post ["A pitfall of Rust's move/copy/drop semantics and zeroing data"](https://benma.github.io/2020/10/16/rust-zeroize-move.html).

There are three levels of "zeroization security" that can be considered, depending on the security goals.

## Pros and cons of different approaches

| Security level | Pros | Cons |
| :---- | :---- | :---- |
| **1** | Provides concrete coding rules for ensuring that a value is zeroed before it is dropped; low coding overhead | Does not achieve guaranteed zeroization; allows compiler to make copies that are not explicitly zeroed |
| **2** | Prevents moves from creating copies or enforces that copies are explicit in the code | Cannot prevent explicit dereferences from creating copies on the stack; more coding overhead |
| **3** | No need to fight with the compiler; provides the best guarantees around data isolation; achieves a conceptually simple model of data’s lifetime and zeroization | Time-consuming to implement; resource-intensive at runtime; does not provide 100% certain memory zeroization because of possible hardware-level uncertainties |

{{< hint info >}}
If you have implemented level 1 or level 2 controls, then use [our `zeroize-audit` skill](https://github.com/trailofbits/skills/tree/main/plugins/zeroize-audit)
to find missing zeroizations and compiler-removed wipes.
{{< /hint >}}

## Security level 1: Use ZeroizeOnDrop (the common practice)

Roughly, the idea is to ensure that values are zeroed whenever they fall out of scope. The [`zeroize`](https://docs.rs/zeroize/latest/zeroize/) crate is the most common way to achieve this goal. Owned values derive the `ZeroizeOnDrop` trait, causing values to call their component’s `zeroize` methods when the compiler inserts a drop on that value. This approach offers a simple model of zeroization where you do not fight the compiler and simply attempt to guarantee that each drop is covered by zeroization.

Unfortunately, moves can, and often do, create copies. These copies happen specifically [when stack values are moved](https://docs.rs/zeroize/latest/zeroize/#stackheap-zeroing-notes). However, ABI constraints or optimization of heap values can also result in a copy.

A simple case of failed zeroization is shown below. A stack value implementing the `ZeroizeOnDrop` trait is moved to the heap ("leak A"): only the heap value is zeroized; the old copy of the secret may remain on the stack.

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
struct Secret {
    key: [u8; 32],
}

fn mac(mut key: [u8; 32], msg: &[u8]) -> u8 {
    let mut tag = 0u8;
    for (i, &b) in msg.iter().enumerate() {
        key[i % 32] ^= b;
        tag ^= key[i % 32];
    }
    tag
}

fn main() {
    let s = Secret { key: [0xab; 32] };        // built on main's stack
    let stored = Box::new(s);                  // LEAK A: stack -> heap move
    let tag = mac(stored.key, b"hello world"); // LEAK B: by-value copy
    println!("tag={:02x}", tag);
}
```

## Security level 2: Zeroization target is not moved or moved explicitly

An alternative to the best-effort approach is to fight the compiler and attempt to guarantee that copies do not live in memory.

You can attempt to prevent spurious compiler-introduced copies created by moves by disallowing moves through the [`pin`](https://doc.rust-lang.org/std/pin/) feature. Using `pin` provides some compile-time safety, as shown in the example below. The "leak A" from level 1 is no longer possible (code won't compile).

```rust
use std::{marker::PhantomPinned, pin::pin};

use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
struct Secret {
    key: [u8; 32],
    #[zeroize(skip)]
    _pin: PhantomPinned,
}

fn mac(mut key: [u8; 32], msg: &[u8]) -> u8 {
    let mut tag = 0u8;
    for (i, &b) in msg.iter().enumerate() {
        key[i % 32] ^= b;
        tag ^= key[i % 32];
    }
    tag
}

fn main() {
    let s = pin!(Secret { key: [0xab; 32], _pin: PhantomPinned });
    // The Level 1 leak no longer type-checks:
    //     let _stored = Box::new(*s);
    //            ^^ cannot move out of dereference of `Pin<&mut Secret>`
    let tag = mac(s.key, b"hello world"); // LEAK B: by-value copy
    println!("tag={:02x}", tag);
}

```

However, this approach still does not prevent unexpected copies of data from being created in the process's memory. The example above still discloses a copy of the secret value on the stack ("leak B"), because of the by-value copy in the call to the `mac` function.

A more involved strategy is to use the [`secrecy`](https://docs.rs/secrecy/latest/secrecy/) crate. It prevents accidental copies of secret data and makes any secret exposure explicit in the code.

```rust
use secrecy::{ExposeSecret, SecretBox};

fn mac(mut key: [u8; 32], msg: &[u8]) -> u8 {
    let mut tag = 0u8;
    for (i, &b) in msg.iter().enumerate() {
        key[i % 32] ^= b;
        tag ^= key[i % 32];
    }
    tag
}

fn main() {
    let s: SecretBox<[u8; 32]> = SecretBox::init_with_mut(|k| *k = [0xab; 32]);

    // Implicit leaks that the type system rejects:
    //     let d: [u8; 32] = *s;         // ERROR: SecretBox does not Deref to its inner T
    // Safe operations (each shown independently; SecretBox is not Copy/Clone):
    //     let moved = s;                // moves the wrapper; no secret copy is made
    //     println!("{:?}", s);          // Debug is redacted: prints "SecretBox<[u8; 32]>([REDACTED])", not the bytes

    // Leak B is now explicit:
    let tag = mac(*s.expose_secret(), b"hello world");
    println!("tag={:02x}", tag);
}
```

A common pitfall with `secrecy` is leaking secret data onto the stack during initialization. To avoid it, use `secrecy`'s in-place initialization APIs such as `init_with_mut` rather than constructing the value first and then wrapping it. The example below is insecure because `key` is built on the stack and only afterwards moved into the heap allocation, leaving a stack copy behind.

```rust
let key = derive_key();
SecretBox::new(Box::new(key))
```

Another shortcoming of the `secrecy` and `pin` solutions is that they do not use `mlock` or similar mechanisms to prevent the OS from writing the secrets into swap or hibernation images.

## Security level 3: Tear down processes, allocators, and the stack intermittently

To really guarantee that data is no longer in memory (though the definition of *guarantee* depends on the kernel, hardware, etc.), you can tear down processes or worker threads and clear all memory associated with them at set points where the data should leave memory (i.e., after a request has been processed). The easiest version of this approach is a worker process that only returns a result and is killed after finishing a request. A more complex version with threads would have to [clear stack and possibly other memory locations explicitly](https://docs.rs/clear_on_drop/latest/clear_on_drop/fn.clear_stack_on_return.html).

This approach effectively relies on the kernel to provide memory-level process isolation. It should prevent compromise of secrets if the main process is compromised. However, it will not prevent secrets from residing in RAM memory until overwritten at some random point in time (the data may be retrieved with specialized lab equipment).

A more complex approach would be to have the code iterate over subprocesses’ and threads’ writable memory regions and overwrite them with zeros or random data just before they are killed. However, even with such an overly complex solution, you may not be sure about data zeroization because a process-level implementation cannot provide guarantees that are effectively hardware-level.
