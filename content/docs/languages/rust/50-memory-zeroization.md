---
title: "Memory zeroization"
slug: lang-rust-memory-zeroization
weight: 50
---

# Rust memory zeroization

Zeroization in the presence of optimizing compilers is difficult. In Rust, it is particularly tricky because of the constraints the compiler imposes on memory management. The compiler can infer significant information about aliasing information that allows unexpected copies of secret data to appear on the stack. For example, consider the pitfall described in the blog post ["A pitfall of Rust's move/copy/drop semantics and zeroing data"](https://benma.github.io/2020/10/16/rust-zeroize-move.html).

There are three levels of "zeroization security" that can be considered, depending on the security goals.

**Pros and cons of different approaches**

| Security level | Pros | Cons |
| :---- | :---- | :---- |
| **1** | Provides concrete coding rules for ensuring that a value is zeroed before it is dropped; low coding overhead | Does not achieve guaranteed zeroization; allows compiler to make copies that are not explicitly zeroed |
| **2** | Prevents moves from creating copies and leaving the parent data on the stack | Cannot prevent downstream dereferences from creating copies on the stack; more coding overhead |
| **3** | No need to fight with the compiler; provides the best guarantees around data isolation; achieves a conceptually simple model of data’s lifetime and zeroization | Time-consuming to implement; resource-expensive in runtime; does not provide 100% certain memory zeroization because of possible hardware-level uncertainties |

## Security level 1: Use ZeroizeOnDrop (the common practice)

Roughly, the idea is to ensure that values are zeroed whenever they fall out of scope. The [`zeroize`](https://docs.rs/zeroize/latest/zeroize/) crate is the most common way to achieve this goal. Owned values derive the `ZeroizeOnDrop` trait, causing values to call their component’s `zeroize` methods when the compiler inserts a drop on that value. This approach offers a simple model of zeroization where you do not fight the compiler and simply attempt to guarantee that each drop is covered by zeroization. This approach can be made easier by using the [`secrecy`](https://docs.rs/secrecy/0.8.0/secrecy/) crate, which provides wrappers around various types.

Unfortunately, moves can, and often do, create copies. These copies happen specifically [when stack values are moved](https://docs.rs/zeroize/latest/zeroize/#stackheap-zeroing-notes). However, ABI constraints or optimization of heap values can also result in a copy.


{{< details "Example to try: failed zeroization" >}}

The simplest case is where a stack value implementing the `ZeroizeOnDrop` trait does not result in zeroization because a value is moved.

```rust
use crypto_bigint::{rand_core::OsRng, Random, U256};

#[derive(zeroize::ZeroizeOnDrop)]
struct X {
    i: U256,
}

impl X {
    fn generate() -> X {
        X {
            i: U256::random(&mut OsRng),
        }
    }

    fn take(self) {
        println!("currently {}", self.i);
        drop(self);
        println!("dropped");
    }
}

fn main() {
    let x = X::generate();
    println!("generated value");
    let ptr: *const X = &x;
    unsafe {
        let svd = (*ptr).i;
        println!("saved");
        x.take();
        println!("dropped");
        let new = (*ptr).i;
        assert_ne!(svd, new); // assertion fails
    }
}
```

{{< /details >}}


## Security level 2: Zeroization target is not moved

An alternative to the best-effort approach is to fight the compiler and attempt to guarantee that copies do not live in memory. You can attempt to prevent spurious compiler-introduced copies created by moves by disallowing moves through the [`pin`](https://doc.rust-lang.org/std/pin/) feature. The code below demonstrates how using the `pin` feature fixes the data disclosure demonstrated in the example above. 

```rust
use std::{ops::Deref, pin::Pin};

use crypto_bigint::{rand_core::OsRng, Random, U256};

#[derive(zeroize::ZeroizeOnDrop)]
struct X {
    i: U256,
}

impl X {
    fn generate() -> X {
        X {
            i: U256::random(&mut OsRng),
        }
    }

    fn take(&self) {
        println!("currently {}", self.i);
        println!("dropped");
    }
}

fn main() {
    let x = Pin::new(Box::new(X::generate()));
    println!("generated value");
    let ptr: *const X = x.deref();
    unsafe {
        let svd = (*ptr).i;
        println!("saved");
        x.take();
        drop(x);
        println!("dropped");
        let new = (*ptr).i;
        assert_ne!(svd, new); // assertion passes
    }
}
```

The [`clear_on_drop`](https://docs.rs/clear_on_drop/latest/clear_on_drop/index.html) crate attempts to achieve this behavior by default and roughly performs the role of `pin` plus `ZeroizeOnDrop`.

However, this approach still does not prevent unexpected copies of data from being created in the process's memory. The example above discloses a copy of the `x` value on the stack, as shown in the assembler code below.

```asm
100002260 e2 23 01 91     add        x2,sp,#0x48
                                               $U11e80:8 = COPY 0x48:8
                                               tmpCY = INT_CARRY sp, $U11e80:8
                                               tmpOV = INT_SCARRY sp, $U11e80:8
                                               $U11f80:8 = INT_ADD sp, $U11e80:8
                                               tmpNG = INT_SLESS $U11f80:8, 0:8
                                               tmpZR = INT_EQUAL $U11f80:8, 0:8
                                               x2 = COPY $U11f80:8
100002264 e9 27 00 f9     str        x9,[sp, #local_78]
                                               $U6500:8 = INT_ADD sp, 0x48:8
                                               STORE ram($U6500:8), x9
```

The dereferenced value ends up stored on the stack because of downstream dereferences. In the example above, the `u256` type implements the `Copy` trait, and the call to the `println` function produces a copy (as the function’s ABI requires). It is almost impossible to precisely control downstream dereferences because you would need to manually review the final compiled binary to check that there are no copies of zeroed data.

## Security level 3: Tear down processes, allocators, and the stack intermittently

To really guarantee that data is no longer in memory (though the definition of *guarantee* depends on the kernel, hardware, etc.), you can tear down processes or worker threads and clear all memory associated with them at set points where the data should leave memory (i.e., after a request has been processed). The easiest version of this approach is a worker process that only returns a result and is killed after finishing a request.

This approach effectively relies on the kernel to provide memory-level process isolation. It should prevent compromise of secrets if the main process is compromised. However, it will not prevent secrets from residing in RAM memory until overwritten at some random point in time (the data may be retrieved with specialized lab equipment).

A more complex approach would be to have the code iterate over subprocesses’ and threads’ writable memory regions and overwrite them with zeros or random data just before they are killed. However, even with such an overly complex solution, you may not be sure about data zeroization because a process-level implementation cannot provide guarantees that are effectively hardware-level.

