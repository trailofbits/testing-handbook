---
title: "Gotchas and footguns"
slug: lang-rust-gotchas-and-footguns
weight: 40
---

# Rust gotchas and footguns

This section provides a checklist that can be used during manual Rust code reviews. The list represents common issues we have encountered during our audits. It is not comprehensive, but it is a good starting point to quickly bootstrap an audit.

## For safe code

{{< checklist >}}

- [ ] Check string comparisons.
	* Often partial-match (`starts_with`, `ends_with`, `contains`) is used instead of equality.
	* Case (in)sensitivity of comparisons often results in issues.
- [ ] Check string conversions to other data types (like `Vec`) and vice versa. These may come with UTF-8 encoding issues. Three options to handle utf8–bytes conversions:
	* `unwrap` \- strict, panics on non-convertible data  
	* `from_utf8_lossy` \- lossy, rewrites invalid utf8 bytes to U+FFFD (replacement character)  
	* `OsStr` \- direct, just returns the bytes
- [ ] Verify that the `with_capacity` method of the `Vec`, `HashMap`, `HashSet`, and `indexmap::IndexSet` types (and possibly other types) is not called with user-controlled data. Large values can lead to denial of service.
	* Also check that the provided capacity is smaller than the `isize::MAX` bytes [to prevent panics](https://doc.rust-lang.org/std/vec/struct.Vec.html#panics).
	* Note that some methods—[like Serde’s `size_hint`](https://github.com/serde-rs/serde/issues/744)—may indirectly expose the `with_capacity` method.
- [ ] Verify that users cannot create arbitrarily deep recursive structs. A drop of such a struct can lead to a stack overflow. (See ["If a Tree Falls in a Forest, Does It Overflow the Stack?](https://matklad.github.io/2022/11/18/if-a-tree-falls-in-a-forest-does-it-overflow-the-stack.html) for an example.)
- [ ] Verify that `std::process::exit` is used sparingly. Calling this function causes a process to exit immediately, thereby sidestepping all registered drop handlers.
- [ ] Verify that proper bounds checks are performed before array accesses. An out-of-bounds array access can lead to denial of service.
- [ ] Verify that proper checks are performed before type conversions to prevent loss of precision (e.g., `u64` to `f64`, as the mantissa of type `f64` is only 52 bits wide).
- [ ] Check that the number of fields passed into the [`serialize_struct` method matches the actual number of serialized fields](https://github.com/trailofbits/dylint/tree/master/examples/general/wrong_serialize_struct_arg). Some serialization formats, such as `serde-binary`, could truncate the serialized data if the number of fields is incorrect. This would mean that deserializing the data would result in a different value than the original.
- [ ] Review all methods and actions that may cause panics. Other sections of the Handbook describe tools that can help with reviewing operations that could lead to panics.
	* `unwrap` and `expect` (the most common panicking methods)
	* [`todo!`,](https://doc.rust-lang.org/std/macro.todo.html) [`unimplemented!`](http://doc.rust-lang.org/std/macro.unimplemented.html), [`assert!`](https://doc.rust-lang.org/std/macro.assert.html) and [`unreachable!`](https://doc.rust-lang.org/std/macro.unreachable.html) macros
	* Out-of-bounds accesses
	* Large allocations
	* String slicing at non-character boundaries
	* `RefCell` 
	  * This struct enforces borrowing rules at runtime, and `borrow_mut` calls may panic.
	* [`HeaderMap`](https://docs.rs/http/latest/http/header/struct.HeaderMap.html#limitations)
	  * This struct panics after more than 32,768 (2^15) elements are added.
	* `Duration::from_secs_f{32,64}` and `Duration::new` 
	  * `Duration::from_secs_f{32,64}` panics with negative inputs; `Duration::new` panics when the nanoseconds value overflows into the seconds counter.
- [ ] Verify that it is not possible to modify keys while they’re in a collection type like a `HashMap` or `BinaryHeap`, as this leads to undefined behavior.
- [ ] Verify that `debug_assert!` and other debug macros are not used for actual data validation. Such macros are removed from production builds.
- [ ] Verify that raw file descriptors are explicitly closed in all execution flow paths. Raw descriptors are not closed on `Drop`.
	* Verify that owned file descriptors are not closed two times: automatically on `Drop` and explicitly via the [`close` method](https://docs.rs/nix/latest/nix/unistd/fn.close.html).
- [ ] Explicitly flush `BufWriter`s to get flush errors; errors are ignored on automatic flushing when values are dropped.
- [ ] Ensure that absolute paths are not used with [`PathBuf::join`](https://doc.rust-lang.org/std/path/struct.PathBuf.html#method.join), as this may lead to path traversal issues.
- [ ] Verify that functions used only in tests are guarded by `#[cfg(test)]`.
- [ ] Verify that each use of `#![allow(...)]` is justified and that `#[allow(...)]` is not used excessively.
- [ ] Operator precedence of bitwise operators (`&`, `^`, `|`) compared to comparison operators (`==`, `!=`) differs between Rust and C. This is something to be aware of when rewriting C code.
- [ ] Verify that test-only Cargo features (like mocks) are not included in `[dependencies]` and are not part of the `default` feature set. Use `cargo tree -e features` to validate your project.
- [ ] Review code against possible issues resulting from operating system interactions (see the [C/C++ chapter for ideas](/docs/languages/c-cpp/)). Any syscall, libc function call, and other interaction with the operating system should be checked against known gotchas.
- [ ] Review the ["Secure Rust Guidelines checklist"](https://anssi-fr.github.io/rust-guide/checklist.html).

{{< /checklist >}}

## For unsafe code

Common issues to check for in unsafe code are given below. For more information, read the [Rustonomicon](https://doc.rust-lang.org/nomicon/intro.html).

{{< checklist >}}

- [ ] Any union access is unsafe in Rust. Verify that the union field that matches the underlying data is used.  
- [ ] Look for uses of libc APIs like `memset` or `memcpy`. Most of them can be replaced with safe Rust counterparts.  
- [ ] If `#[repr(packed)]` is used on a struct, then check that [`write_unaligned`](https://doc.rust-lang.org/std/ptr/fn.write_unaligned.html#on-packed-structs) is used for unaligned fields.  
- [ ] Check for uses of [`std::mem::uninitialized`](https://doc.rust-lang.org/std/mem/fn.uninitialized.html).  
- [ ] Check for uses of [`std::mem::forget`](https://doc.rust-lang.org/std/mem/fn.forget.html).  
- [ ] Check for uses of `transmute` or `cast` from a non-mutable reference `&` to a mutable `&mut` (likely an undefined behavior).  
- [ ] Review uses of `static mut` and [recommend using synchronization instead](https://github.com/rust-lang/rust/issues/53639).

{{< /checklist >}}