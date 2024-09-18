---
title: "Python"
slug: python
weight: 3
---


# Python

We recommend using [Atheris](https://github.com/google/atheris) to fuzz Python code.

## Installation

Atheris supports 32-bit and 64-bit Linux, and macOS. We recommend fuzzing on Linux because it's simpler to manage and often faster. If you'd like to run Atheris in a Linux environment on a Mac or Windows system, we recommend using [Docker Desktop](https://www.docker.com/products/docker-desktop/).

If you'd like a fully operational Linux environment, see the [`Dockerfile`](#dockerfile) section below.

If you'd like to install Atheris locally, first install a recent version of `clang`, preferably the [latest release](https://github.com/llvm/llvm-project/releases), then run the following command:

```bash
python -m pip install atheris
```

{{< hint info >}}
Atheris is built on libFuzzer, so consider reading [our section]({{% ref "docs/fuzzing/c-cpp/10-libfuzzer/index.md" %}}) on that too.
{{< /hint >}}

## Usage

### Fuzzing pure Python code

With a working Atheris environment, let's fuzz some Python code.

Start by saving the following as `fuzz.py`:

```python
import sys
import atheris

@atheris.instrument_func
def test_one_input(data: bytes):
    if len(data) == 4:
        if data[0] == 0x46:  # "F"
            if data[1] == 0x55:  # "U"
                if data[2] == 0x5A:  # "Z"
                    if data[3] == 0x5A:  # "Z"
                        raise RuntimeError("You caught me")

def main():
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
```

Then run Atheris with the following command:

```bash
python fuzz.py
```

Relatively quickly, it should produce a crash like the following:

```bash
INFO: Using preloaded libfuzzer
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 3701051567
INFO: Loaded 2 modules   (15334 inline 8-bit counters): 9595 [0xffff951f58e0, 0xffff951f7e5b), 5739 [0xffff94f843e0, 0xffff94f85a4b),
INFO: Loaded 2 PC tables (15334 PCs): 9595 [0xffff951f7e60,0xffff9521d610), 5739 [0xffff94f85a50,0xffff94f9c100),
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
INFO: A corpus is not provided, starting from an empty corpus
#2  INITED cov: 882 ft: 883 corp: 1/1b exec/s: 0 rss: 66Mb
#3  NEW    cov: 882 ft: 885 corp: 2/3b lim: 4 exec/s: 0 rss: 66Mb L: 2/2 MS: 1 CopyPart-
#13 NEW    cov: 884 ft: 1257 corp: 3/7b lim: 4 exec/s: 0 rss: 67Mb L: 4/4 MS: 5 CrossOver-ChangeBinInt-ChangeByte-ChangeBinInt-CopyPart-
#65536  pulse  cov: 884 ft: 1257 corp: 3/7b lim: 652 exec/s: 21845 rss: 98Mb
#71462  NEW    cov: 886 ft: 1379 corp: 4/11b lim: 706 exec/s: 17865 rss: 101Mb L: 4/4 MS: 4 ChangeBinInt-ChangeByte-ChangeBit-CopyPart-
#131072 pulse  cov: 886 ft: 1379 corp: 4/11b lim: 1290 exec/s: 21845 rss: 130Mb
#230788 NEW    cov: 888 ft: 1691 corp: 5/15b lim: 2281 exec/s: 25643 rss: 177Mb L: 4/4 MS: 1 ChangeByte-
#262144 pulse  cov: 888 ft: 1691 corp: 5/15b lim: 2589 exec/s: 26214 rss: 194Mb
#287560 NEW    cov: 890 ft: 1704 corp: 6/19b lim: 2842 exec/s: 26141 rss: 208Mb L: 4/4 MS: 2 InsertByte-EraseBytes-

 === Uncaught Python exception: ===
RuntimeError: You caught me
Traceback (most recent call last):
  File "/app/fuzz.py", line 11, in test_one_input
    raise RuntimeError("You caught me")
RuntimeError: You caught me

==399== ERROR: libFuzzer: fuzz target exited
    #0 0xffff989df9b8 in __sanitizer_print_stack_trace (/opt/venv/lib/python3.11/site-packages/asan_with_fuzzer.so+0x11f9b8) (BuildId: b12d6567a22f7311b104efa346c5035b6837d8d1)
    #1 0xffff989344cc in fuzzer::PrintStackTrace() (/opt/venv/lib/python3.11/site-packages/asan_with_fuzzer.so+0x744cc) (BuildId: b12d6567a22f7311b104efa346c5035b6837d8d1)
    #2 0xffff9891a7c8 in fuzzer::Fuzzer::ExitCallback() (/opt/venv/lib/python3.11/site-packages/asan_with_fuzzer.so+0x5a7c8) (BuildId: b12d6567a22f7311b104efa346c5035b6837d8d1)
    #3 0xffff9822ce88  (/lib/aarch64-linux-gnu/libc.so.6+0x3ce88) (BuildId: 918ff46614b9808b05f1e29a9914132def52f69e)
    #4 0xffff9822cf5c in exit (/lib/aarch64-linux-gnu/libc.so.6+0x3cf5c) (BuildId: 918ff46614b9808b05f1e29a9914132def52f69e)
    #5 0xffff9852eba8 in Py_Exit (/usr/local/bin/../lib/libpython3.11.so.1.0+0x18eba8) (BuildId: 3e68e83acff0ce909056da94a6b647416bc78ec5)
    #6 0xffff9852ebd8  (/usr/local/bin/../lib/libpython3.11.so.1.0+0x18ebd8) (BuildId: 3e68e83acff0ce909056da94a6b647416bc78ec5)
    #7 0xffff9852ec34  (/usr/local/bin/../lib/libpython3.11.so.1.0+0x18ec34) (BuildId: 3e68e83acff0ce909056da94a6b647416bc78ec5)
    #8 0xffff98601af8 in _PyRun_SimpleFileObject (/usr/local/bin/../lib/libpython3.11.so.1.0+0x261af8) (BuildId: 3e68e83acff0ce909056da94a6b647416bc78ec5)
    #9 0xffff9860172c in _PyRun_AnyFileObject (/usr/local/bin/../lib/libpython3.11.so.1.0+0x26172c) (BuildId: 3e68e83acff0ce909056da94a6b647416bc78ec5)
    #10 0xffff985fa04c in Py_RunMain (/usr/local/bin/../lib/libpython3.11.so.1.0+0x25a04c) (BuildId: 3e68e83acff0ce909056da94a6b647416bc78ec5)
    #11 0xffff985a1ef4 in Py_BytesMain (/usr/local/bin/../lib/libpython3.11.so.1.0+0x201ef4) (BuildId: 3e68e83acff0ce909056da94a6b647416bc78ec5)
    #12 0xffff9821773c  (/lib/aarch64-linux-gnu/libc.so.6+0x2773c) (BuildId: 918ff46614b9808b05f1e29a9914132def52f69e)
    #13 0xffff98217814 in __libc_start_main (/lib/aarch64-linux-gnu/libc.so.6+0x27814) (BuildId: 918ff46614b9808b05f1e29a9914132def52f69e)
    #14 0xaaaae095086c in _start (/usr/local/bin/python3.11+0x86c) (BuildId: 4556bff17c135ffcd799fb46df15a21e0c671da8)

SUMMARY: libFuzzer: fuzz target exited
MS: 1 CopyPart-; base unit: cc3a45e08551b2e1d4f50d233a2a1b6c24f6dee8
0x46,0x55,0x5a,0x5a,
FUZZ
artifact_prefix='./'; Test unit written to ./crash-aea2e3923af219a8956f626558ef32f30a914ebc
Base64: RlVaWg==
```

As you can see, it found the input that produces an exception: `"FUZZ"`. This example highlights Atheris' ability to instrument and track coverage in pure Python code. More typically you will want to use something like [`atheris.instrument_imports` or `atheris.instrument_all`](https://github.com/google/atheris#python-coverage) to fuzz broader parts of an application or library.

To fuzz your own target, modify the `test_one_input` function to call your target function.

### Fuzzing Python C extensions

Fuzzing Python C extensions requires a bit more work. They must be compiled with the correct compiler flags. If you're using the provided [`Dockerfile`](#dockerfile), they should already be set for you (`CC`, `CFLAGS`, `LD_PRELOAD`, etc.).

Let's fuzz the [`cbor2`](https://github.com/agronholm/cbor2) project as an example. It includes a Python C extension component and binary data parsing functionality, which is particularly amenable to fuzzing.

First, install the package:

```bash
CBOR2_BUILD_C_EXTENSION=1 python -m pip install --no-binary cbor2 cbor2==5.6.4
```

The `CBOR2_BUILD_C_EXTENSION` environment variable and `--no-binary` flag ensure that the C extension code is compiled locally rather than using pre-compiled binaries. This allows us to instrument fuzzing and [`AddressSanitizer`](https://clang.llvm.org/docs/AddressSanitizer.html) functionality into the compiled object.

Start by saving the following as `cbor2-fuzz.py`:

```python
import sys
import atheris

# _cbor2 ensures the C library is imported
from _cbor2 import loads

def test_one_input(data: bytes):
    try:
        loads(data)
    except Exception:
        # We're searching for memory corruption, not Python exceptions
        pass

def main():
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
```

Then run Atheris with the following command:

```bash
python cbor2-fuzz.py
```

This will start fuzzing `cbor2`, but you should not expect a crash unless you get lucky and find a bug. This example serves as a demonstration of fuzzing an existing Python C extension.

{{< hint info >}}
Remember, if you're running this locally and not in the provided Docker image, then you'll need to [set `LD_PRELOAD` manually](https://github.com/google/atheris/blob/master/native_extension_fuzzing.md#option-a-sanitizerlibfuzzer-preloads).
{{< /hint >}}

## Additional resources

- [Continuously fuzzing Python C extensions](https://blog.trailofbits.com/2024/02/23/continuously-fuzzing-python-c-extensions/)
- [Fuzzing pure Python code](https://github.com/google/atheris#using-atheris)
- [Fuzzing Python C extensions](https://github.com/google/atheris/blob/master/native_extension_fuzzing.md)
- [Fuzzing Python in CI](https://google.github.io/clusterfuzzlite//build-integration/python-lang/)

### Dockerfile

To use Atheris in a Docker environment, save the following code in the `Dockerfile`:

```dockerfile
# https://hub.docker.com/_/python
ARG PYTHON_VERSION=3.11

FROM python:$PYTHON_VERSION-slim-bookworm

RUN python --version

RUN apt update && apt install -y \
    ca-certificates \
    wget \
    && rm -rf /var/lib/apt/lists/*

# LLVM builds version 15-19 for Debian 12 (Bookworm)
# https://apt.llvm.org/bookworm/dists/
ARG LLVM_VERSION=19

RUN echo "deb http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-$LLVM_VERSION main" > /etc/apt/sources.list.d/llvm.list
RUN echo "deb-src http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-$LLVM_VERSION main" >> /etc/apt/sources.list.d/llvm.list
RUN wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key > /etc/apt/trusted.gpg.d/apt.llvm.org.asc

RUN apt update && apt install -y \
    build-essential \
    clang-$LLVM_VERSION \
    && rm -rf /var/lib/apt/lists/*

ENV APP_DIR "/app"
RUN mkdir $APP_DIR
WORKDIR $APP_DIR

ENV VIRTUAL_ENV "/opt/venv"
RUN python -m venv $VIRTUAL_ENV
ENV PATH "$VIRTUAL_ENV/bin:$PATH"

# https://github.com/google/atheris/blob/master/native_extension_fuzzing.md#step-1-compiling-your-extension
ENV CC="clang-$LLVM_VERSION"
ENV CFLAGS "-fsanitize=address,fuzzer-no-link"
ENV CXX="clang++-$LLVM_VERSION"
ENV CXXFLAGS "-fsanitize=address,fuzzer-no-link"
ENV LDSHARED="clang-$LLVM_VERSION -shared"
ENV LDSHAREDXX="clang++-$LLVM_VERSION -shared"
ENV ASAN_SYMBOLIZER_PATH="/usr/bin/llvm-symbolizer-$LLVM_VERSION"

# Allow Atheris to find fuzzer sanitizer shared libs
# https://github.com/google/atheris#building-from-source
RUN LIBFUZZER_LIB=$($CC -print-file-name=libclang_rt.fuzzer_no_main-$(uname -m).a) \
    python -m pip install --no-binary atheris atheris

# https://github.com/google/atheris/blob/master/native_extension_fuzzing.md#option-a-sanitizerlibfuzzer-preloads
ENV LD_PRELOAD "$VIRTUAL_ENV/lib/python3.11/site-packages/asan_with_fuzzer.so"

# 1. Skip memory allocation failures for now, they are common, and low impact (DoS)
# 2. https://github.com/google/atheris/blob/master/native_extension_fuzzing.md#leak-detection
ENV ASAN_OPTIONS "allocator_may_return_null=1,detect_leaks=0"

CMD ["/bin/bash"]
```

Then run the following commands to build and run the container:
- `docker build -t atheris .`
- `docker run -it atheris`

Note you may need to modify `CFLAGS` and `CXXFLAGS` if you'd like to [use UBSAN](https://llvm.org/docs/LibFuzzer.html#fuzzer-usage).
