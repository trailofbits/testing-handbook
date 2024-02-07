---
title: "Writing harnesses"
slug: writing-harnesses
summary: "TODO"
weight: 1
---

### Writing harnesses {#writing-harnesses}

The following section showcases some techniques to successfully write a fuzzing harness—the most important part of any fuzzing setup. If written poorly, critical parts of your application may not be covered.


#### Beyond byte arrays {#beyond-byte-arrays}

Often the code you want to fuzz not only takes a plain byte array as input, but has more complex input. A very basic example is the following fuzz test that contains a division by 0. Because the inputs to the function `divide` are two integers, we must be creative and derive those from the byte array. We do that by simply casting the raw bytes to 32-bit integers. Note that the byte array may be interpreted differently depending on the system architecture (i.e., little vs. big-endian systems).

Any fuzzer using the following harness will find the bug quickly.



{{< customFigure "" "html" >}}
{{< tabs "beyond" >}}
{{< tab "C/C++" >}}
```C++
#include <stdint.h>
#include <stdlib.h>

double divide(uint32_t numerator, uint32_t denominator) {
    // Bug: No check if denominator is zero
    return numerator / denominator;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure exactly 2 4-byte numbers (numerator and denominator) are read
    if(size != 2 * sizeof(uint32_t)){
        return 0;
    }

    // Split input into numerator and denominator
    int numerator = *(uint32_t*)(data);
    int denominator = *(uint32_t*)(data + sizeof(uint32_t));

    divide(numerator, denominator);

    return 0;
}
```

{{< /tab >}}

{{< tab "Rust" >}}
```Rust
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::slice;

pub fn divide(numerator: i32, denominator: i32) -> i32 {
    // Rust automatically checks for division by zero at runtime,
    // so we don't need an explicit check.
    numerator / denominator
}

fuzz_target!(|data: &[u8]| {
    if data.len() != 2 * std::mem::size_of::<i32>() {
        return;
    }

    // Split input into numerator and denominator
    let numerator = i32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
    let denominator = i32::from_ne_bytes([data[4], data[5], data[6], data[7]]);

    divide(numerator, denominator);
});
```
{{< /tab >}}
{{< /tabs >}}
{{< /customFigure >}}


If we move to a more complicated C/C++ example like the following string concatenation function, then we might want to use the helper class [`FuzzedDataProvider`](https://github.com/llvm/llvm-project/blob/main/compiler-rt/include/fuzzer/FuzzedDataProvider.h). The header can be copied into a project and used as follows:

```C++
#include <stdint.h>
#include <stdlib.h>
#include "./FuzzedDataProvider.h"

char* concat(const char* inputStr, size_t inputStrLen,
    const char* anotherStr, size_t anotherStrLen,
    size_t allocation_size) {

    if (allocation_size <= 1 || allocation_size > 1 << 16) {
        return NULL;
    }

    char* result = (char*)malloc(allocation_size);

    if (result == NULL) {
        return NULL;
    }

    memcpy(result, inputStr, inputStrLen);
    memcpy(result + inputStrLen, anotherStr, anotherStrLen);

    return result;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);

    size_t allocation_size = fuzzed_data.ConsumeIntegral<size_t>();

    std::vector<char> str1 =
        fuzzed_data.ConsumeBytesWithTerminator<char>(32, 0xFF);

    std::vector<char> str2 =
        fuzzed_data.ConsumeBytesWithTerminator<char>(32, 0xFF);

    char* concatenated = concat(&str1[0], str1.size(), &str2[0], str2.size(), allocation_size);
    if (concatenated != NULL) {
        free(concatenated);
    }

    return 0;
}
```


The above example fuzzes the concat function with parameters for receiving two C-style strings and a maximum allocation size. However, the above function contains a bug:the sum of the strings’ lengths is not checked against the allocation size. Therefore, if the allocation size is too small, the `memcpy` function will cause a buffer overflow.

The harness function `LLVMFuzzerTestOneInput` uses the `FuzzedDataProvider` to read an integer and then two data strings. The length of the data strings is determined by a separator.

Internally, the `FuzzedDataProvider` class handles consuming variable-length data. For the first string, we use the magic value `0xFF` to delimit the string from other data. For example, if our input consists only of two strings, we can use the value `\FF` to separate inputs: `Hello World\FFHello Trail of Bits\FF`.

When mixing strings and integers, we may have to resort to a more complex separator like `0xB105F00D`. Theoretically, we can then split inputs using this value: `Hello World\xB1\x05\xF0\x0DHello Trail of Bits\xB1\x05\xF0\x0D\x0F`. However, note that this is not possible with `FuzzedDataProvider` because the data type of the separator must match the type of data. If you are dealing with byte arrays, the separator can be only a single byte.

The above technique discussed in this section is also discussed in the [Google documentation for libFuzzer](https://github.com/google/fuzzing/blob/master/docs/split-inputs.md). 

A more advanced use case is structured fuzzing, as  highlighted in the following pro tip. Generally, structured fuzzing requires more setup, but allows for improved fuzzing performance because mutations can not render inputs unparsable.


{{< hint info >}}
PRO TIP: If we generalize the idea above, we conclude that we often want some sort of data format. In the above case, the format is simple. We expect two integers in an 8-byte array. A more complex format could allow arbitrary data to be encoded. 

However, note that most data formats are not useful for this task because minor modifications by the fuzzer invalidate the whole input. For example, removing or altering a single character (e.g. the `2`) from a JSON file can cause parsers to fail on deserializers.
```json
{
    "numerator": 9,
    "denominator": 2̶
}
```

By contrast, flipping any bit in a binary input data format produces a new and potentially interesting input (the fuzzer just has to learn that every input is exactly 8 bytes).

In summary: If your program expects complex input, think in terms of a suitable data format.

If your input is highly structured, you may want to look into libFuzzer's [custom mutators that fuzz fields of protobuf messages](https://github.com/google/fuzzing/blob/master/docs/structure-aware-fuzzing.md#protocol-buffers-as-intermediate-format). Protobuf is used as input data format, and customized mutators ensure that you are fuzzing the contents and not the protobuf format itself. This is already close to a grammar fuzzer.
{{< /hint >}}





#### Interleaved fuzzing {#interleaved-fuzzing}

Input to the fuzzing harness may be used to steer which code within the target is executed. This can be useful when exercising multiple related APIs in a target. Take the following example where multiple arithmetic operations are available. All operations take exactly two doubles as input. We can write a single fuzzing harness that executes all functions based on the first byte in the input.

The code below defines a harness and implements a SUT that can add, subtract, multiply, and divide integers. The harness takes the first byte and then decides to execute one of the instructions based on it. It then parses two integers from the input and invokes the arithmetic operation. The harness also makes sure that the input is sufficiently long.

To prevent the implementation from crashing,  the `divide` function must check that the divisor is non-zero and that no overflow occurs during the division. Afterwards, the resulting value is printed such that the compiler does and removes the call to the arithmetic functions (i.e., `add`, `subtract`, `multiply`, and `divide`) due to compilation optimizations.


{{< customFigure "" "html" >}}
{{< tabs "interleaved" >}}
{{< tab "C/C++" >}}
```C++
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>

int32_t add(int32_t a, int32_t b);
int32_t subtract(int32_t a, int32_t b);
int32_t multiply(int32_t a, int32_t b);
int32_t divide(int32_t a, int32_t b);

int32_t add(int32_t a, int32_t b) {
    return a + b;
}

int32_t subtract(int32_t a, int32_t b) {
    return a - b;
}

int32_t multiply(int32_t a, int32_t b) {
    return a * b;
}

int32_t divide(int32_t a, int32_t b) {
    // Avoid division by zero and int overflow
    if (b != 0 && !(a == INT_MIN && b == -1)) {
        return a / b;
    }
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1 + 2 * sizeof(int32_t)) {
        return 0;
    }

    uint8_t mode = data[0];
    int32_t numbers[2];
    int32_t r = 0;
    memcpy(numbers, data + 1, 2 * sizeof(int32_t));

    // We select functions based on the first byte of the fuzzing data
    switch (mode % 4) {
    case 0:
        r = add(numbers[0], numbers[1]);
        break;
    case 1:
        r = subtract(numbers[0], numbers[1]);
        break;
    case 2:
        r = multiply(numbers[0], numbers[1]);
        break;
    case 3:
        r = divide(numbers[0], numbers[1]);
        break;
    }

    printf("%d", r);

    return 0;
}
```
{{< /tab >}}

{{< tab "Rust" >}}
```Rust
#![no_main]
use libfuzzer_sys::fuzz_target;

pub trait Arithmetic: Sized {
    fn add(self, other: Self) -> Self;
    fn subtract(self, other: Self) -> Self;
    fn multiply(self, other: Self) -> Self;
    fn divide(self, other: Self) -> Option<Self>;
}

impl Arithmetic for f64 {
    fn add(self, other: Self) -> Self {
        self + other
    }

    fn subtract(self, other: Self) -> Self {
        self - other
    }

    fn multiply(self, other: Self) -> Self {
        self * other
    }

    fn divide(self, other: Self) -> Option<Self> {
        if other == 0.0 { None } else { Some(self / other) }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 1 + 2 * std::mem::size_of::<f64>() {
        return;  // Not enough data for mode and two f64 numbers
    }

    let mode = data[0];
    let numbers = &data[1..];

    if let [first, second] = *bytemuck::try_cast_slice::<_, f64>(numbers).unwrap_or_else(|_| &[0.0, 0.0]) {
        match mode % 4 {
            0 => { first.add(second); },
            1 => { first.subtract(second); },
            2 => { first.multiply(second); },
            3 => { first.divide(second); },
            _ => {}
        }
    }
});
```
{{< /tab >}}
{{< /tabs >}}
{{< /customFigure >}}


There are multiple advantages to interleaved fuzzing:
* Depending on the target, it may be quicker to write a single harness that exercises a larger surface than individual fuzzing harnesses.
* Using a single harness also means using a single corpus. Therefore, ensure that test cases are relevant across the implemented operations or fuzz tests. Inputs interesting for division may also be interesting for subtraction.


#### Practical harness rules {#practical-harness-rules}

Even though harnesses can execute arbitrary code, a few rules are beneficial to follow when implementing harnesses. We adapted these from the official libFuzzer [documentation](https://llvm.org/docs/LibFuzzer.html#id23).

In fact, these guidelines don’t just apply to the harness code, but also to the entire codebase of the SUT. Refer to the SUT Patching: Overcoming obstacles section to learn how to patch SUTs for [C/C++]({{% relref "/docs/fuzzing/c-cpp/techniques/02-obstacles#sut-patching-overcoming-obstacles" %}}) and [Rust]({{% relref "/docs/fuzzing/rust/techniques/02-obstacles#sut-patching-overcoming-obstacles" %}}).

The following points should be considered when implementing fuzzing harnesses regardless of the language they are written in:



* A harness must handle all kinds of input, such as empty, huge, or malformed inputs. For instance, large inputs should not cause unexpected out of memory issues because of code in the harness. \
**Rationale:** The fuzzer calls the harness with random input, so the harness must be prepared to handle all inputs in a defined way.
* It must not call the [`exit`](https://linux.die.net/man/3/exit) function. \
**Rationale:** Calling exit causes the whole process to stop, including the fuzzing. If you want to signal an unrecoverable situation, then call [`abort`](https://linux.die.net/man/3/abort) in your SUT.

* If threads are used, then all threads must be [`joined`](https://linux.die.net/man/3/pthread_join) at the end of the `LLVMFuzzerTestOneInput` function. \
**Rationale:** Each invocation should be done in isolation and run to completion before continuing with the next fuzzing test case.
* Harnesses should be fast, avoiding high complexity, logging, or excess memory use. \
**Rationale:** Speed plays a huge role in the success of fuzzing. Executing the SUT quickly is important to get enough executions per second (usually 100s to 1000s executions per core). Low memory usage allows parallel fuzzing on more cores.
* Harnesses should maintain determinism and avoid non-determinism like random and non-input-based decisions. For example, avoid reading from `/dev/random`. \
**Rationale:** If the SUT crashes, then this crash should be reproducible after the fuzzing campaign finishes. By adding non-determinism to the harness, it is likely that the bug occurs only once during fuzzing but is not reproducible.
* Changes to the global state should be avoided where possible. For example, avoid calling [rand](https://linux.die.net/man/3/rand) that depends on the global state of the [PRNG](https://en.wikipedia.org/wiki/Pseudorandom_number_generator). Using the [singleton](https://en.wikipedia.org/wiki/Singleton_pattern) pattern involves global state and should be avoided. \
**Rationale:** Similar to non-determinism, global state can cause test cases to crash only during fuzzing but not afterwards, and therefore can limit reproducibility. For example, suppose a singleton collects data samples while the SUT is running, but allows only `n` samples to be collected before crashing. If the global state is not reset after each execution, then the SUT may crash after `n` executions—not because of the input in the `n`-th execution, but because of the global state.
* Narrow targets are preferred; multiple unrelated data formats should be split into individual targets. \
**Rationale:** Fuzzing PNG and TCP packets in a single campaign probably does not make much sense, because the corpus entries found for PNG are most likely not relevant for fuzzing TCP packets.
