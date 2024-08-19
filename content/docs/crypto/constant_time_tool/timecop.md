---
title: "Timecop"
weight: 50
# bookFlatSection: false
# bookToc: true
# bookHidden: false
# bookCollapseSection: false
# bookComments: false
# bookSearchExclude: false
---

# Timecop (~~Valgrind~~)

[Timecop](https://post-apocalyptic-crypto.org/timecop/) is a wrapper around [Valgrind](https://valgrind.org/) designed to dynamically detect potential timing leaks.
It allows developers to mark memory regions as secret, and if during runtime, a branching instruction or memory access is performed that is dependent on the secret memory region, Valgrind will report the behavior, helping to identify timing vulnerabilities.

## Overview

Timecop is a C macro wrapper around functions provided by Valgrind.

## Setup

To use Timecop, you must first install Valgrind.
Ensure your platform is supported by checking the [supported platforms](https://valgrind.org/info/platforms.html).
{{< tabs "beyond" >}}
{{< tab "Debian & Ubuntu" >}}

```bash
sudo apt-get install valgrind
```

{{< /tab >}}
{{< tab "Arch Linux" >}}

```bash
sudo pacman -S valgrind
```

{{< /tab >}}
{{< tab "Fedora" >}}

```bash
sudo yum -y install valgrind
```

{{< /tab >}}
{{< tab "Mac (Intel based)" >}}

```bash
brew install valgrind
```

{{< /tab >}}
{{< /tabs >}}

Verify the installation with:

```bash
valgrind --version
```

After the installation of Valgrind, all that is needed is to include the header file `poison.h` of TimeCop, which can be found [here](https://post-apocalyptic-crypto.org/timecop/#source-code)

```C
#include "poison.h"
```

Alternatively, use Valgrind's memory-checking functions directly by including the `memceck` library:

```C
#include "valgrind/memcheck.h"

// VALGRIND_MAKE_MEM_UNDEFINED(addr, len)
// VALGRIND_MAKE_MEM_DEFINED(addr, len)
// VALGRIND_CHECK_MEM_IS_DEFINED(addr, len)
```

## Valgrind Background

Valgrind is a powerful tool that tracks memory operations during execution and reports violations such as memory leaks or use-after-free violations.
The effects of memory violations are often not directly apparent, making it difficult to detect them, which is why Valgrind has become a popular tool.
Valgrind works by running the binary on a synthetic CPU created by Valgrind and does not introduce any instrumentations during the compilation process.
Doing so allows it to run on any binary and makes debugging more straightforward, but it comes at the cost of runtime performance.

### Uninitialized Variables

One of the memory violations Valgrind can track is the usage of *uninitialized variables*.
For example:

```C
int a;
```

Using the value of these uninitialized variables in languages like C corresponds to undefined behavior and should, therefore, be avoided.
Valgrind tracks the usage of uninitialized variables and allows them to propagate to other values and memory regions.
Once the program uses the uninitialized values for either a

- *Conditional jump*: Altering the execution trace
- *Move*: Altering the memory access patterns
Valgrind will issue a report.

Consider the following example of the propagation of uninitialized values:

```C
 1 │ int main(){
 2 │     int x;
 3 │     int z[10] = {0};
 4 │     int y = x + 1;
 5 │     int a = z[y];
 6 │     return 0;
 7 │ }
```

Running Valgrind on a binary with debug symbols enabled will generate a report pinpointing where uninitialized values are used.

```bash
> valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./main
...
==49626== Use of uninitialised value of size 8
==49626==    at 0x10916F: main (main.c:5)
==49626==  Uninitialised value was created by a stack allocation
==49626==    at 0x109139: main (main.c:1)
...
```

## Timecop Macros

Timecop uses Valgrind's capabilities to track uninitialized values as a proxy for detecting constant time violations. It uses Valgrind's internal functionality to manually declare memory regions as undefined and wraps these internal functions in C macros.  

It provides three C macros:

- `poison(addr, len)`: Marks the memory region from `[addr] <-> [addr+len]` as undefined. Valgrind will report any conditional jumps or memory accesses during runtime.
- `unpoison(addr, len)`: Undoes the poison operation by marking the memory region as defined.
- `is_poisoned(addr, len)`: Checks if any part of the memory region is poisoned.

Since many constant time violations occur due to memory access or control flow changes, which depend on a secret value, using Valgrind's ability to track these operations can help developers find timing vulnerabilities.  
Importantly, Valgrind does not report any other operations performed on the secret value, such as math operations.

## Example

Below is a simple example of a modular exponentiation operation used in RSA, which we described in the intro section.

```C
  1 │ #include <stdio.h>
  2 │ 
  3 │ #include "valgrind/memcheck.h"
  4 │ 
  5 │ #define poison(addr, len) VALGRIND_MAKE_MEM_UNDEFINED(addr, len)
  6 │ #define unpoison(addr, len) VALGRIND_MAKE_MEM_DEFINED(addr, len)
  7 │ #define is_poisoned(addr, len) VALGRIND_CHECK_MEM_IS_DEFINED(addr, len)
  8 │ 
  9 │ typedef unsigned long long ull;
 10 │ 
 11 │ ull mod_exp(ull y, ull d, ull n) {
 12 │     ull r = 1;
 13 │     y = y % n;
 14 │     while (d > 0) {
 15 │         if (d & 1) {
 16 │             r = (r * y) % n;
 17 │         }
 18 │         y = (y * y) % n;
 19 │         d >>= 1;
 20 │     }
 21 │     return r;
 22 │ }
 23 │ 
 24 │ ull rsa_decrypt(ull ct, ull d, ull n) {
 25 │     return mod_exp(ct, d, n);
 26 │ }
 27 │ 
 28 │ int main() {
 29 │     ull n = 3233;
 30 │     ull d = 413;
 31 │     ull ciphertext = 2790;
 32 │     // Poison the memory location of the secret exponent d
 33 │     poison(&d, sizeof(ull));
 34 │     ull plaintext = rsa_decrypt(ciphertext, d, n);
 35 │     unpoison(&d, sizeof(ull));
 36 │ 
 37 │     printf("pt: %llu\n", plaintext);
 38 │     return 0;
 39 │ }
```

Poisoning the memory region of the private exponent `d` will mark this value as uninitialized, and Valgrind will report any branching or memory access based on the secret exponent `d`.
Valgrind correctly identifies the problematic lines of code where the timing assumptions are not met.

```none
> valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./toy_example

==72317== Conditional jump or move depends on uninitialised value(s)
==72317==    at 0x40115D: mod_exp (toy_example.c:14)
==72317==    by 0x4011E4: rsa_decrypt (toy_example.c:25)
==72317==    by 0x4012B7: main (toy_example.c:34)
==72317==  Uninitialised value was created by a client request
==72317==    at 0x40128C: main (toy_example.c:33)
==72317== 
==72317== Conditional jump or move depends on uninitialised value(s)
==72317==    at 0x40116F: mod_exp (toy_example.c:15)
==72317==    by 0x4011E4: rsa_decrypt (toy_example.c:25)
==72317==    by 0x4012B7: main (toy_example.c:34)
==72317==  Uninitialised value was created by a client request
==72317==    at 0x40128C: main (toy_example.c:33)
```

### Valgrind Debugging with GDB Integration

Valgrind integrates with [GDB](https://www.sourceware.org/gdb/), automatically breaking on all error found by Valgrind and abstracts away the process emulation layer of Valgrind itself allowing for easy debugging.
For a more informative GDB experience, consider using [pwndbg](https://github.com/pwndbg/pwndbg).

To start debugging run:

```bash
valgrind --vgdb=yes --vgdb-error=0 ./<binary>
```

which tells Valgrind to start in GDB mode and break before executing the binary.
Valgrind will print out instructions on how to debug the binary using GDB.
Doing so requires launching GDB with the correct binary, and after GDB has launched

```bash
gdb ./<binary>
> target remote | vgdb
```

GDB will now connect to Valgrind and stop at any reported errors.

## Limitations

1. **Microarchitecture Leakage**: TimeCop and Valgrind cannot detect if individual instructions take more time depending on the input they are provided.
2. **Coverage**: This approach won't find potential vulnerabilities if the vulnerable code is not executed during the runtime.

An alternative approach using [MemorySanitizer](https://clang.llvm.org/docs/MemorySanitizer.html) in Clang offers similar benefits without requiring a library but modifies the binary at compile time. More information and a tutorial are available [here](https://crocs-muni.github.io/ct-tools/tutorials/memsan).
