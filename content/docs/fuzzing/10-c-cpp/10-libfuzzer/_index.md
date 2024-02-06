---
title: "libFuzzer"
slug: libfuzzer
summary: "TODO"
weight: 2
---


# libFuzzer {#libfuzzer}

libFuzzer is the clear and easy choice if you need to fuzz your C/C++ program, because it is part of the LLVM project and is available on most platforms. We recommend fuzzing on Linux if possible because it is the platform with the best support for libFuzzer (e.g., it is not preinstalled in XCode with macOS). Microsoft’s MSVC compiler has recently [gained support for libFuzzer](https://learn.microsoft.com/en-us/cpp/build/reference/fsanitize?view=msvc-170).

Note that libFuzzer has been in [maintenance-only](https://llvm.org/docs/LibFuzzer.html#id13) mode since late 2022, so no new features will be added. However, it is easier to install and use than its alternatives, has wide support, and will still be maintained for the foreseeable future. Therefore, Trail of Bits recommends using libFuzzer for your first fuzzing experiments. 

The more performant AFL++ fuzzer is compatible with fuzzing harnesses written for libFuzzer, which means transitioning from libFuzzer to AFL++ is easy and requires only changing your compiler from `clang++` to `afl-clang-fast++`.

{{< fuzzing/intro-os >}}
If possible, we recommend fuzzing on a local x64_64 VM or renting one on DigitalOcean, AWS, Hetzner, etc.


## Installation {#installation}

If you use Ubuntu or Debian, you can install the `clang` package—which includes libFuzzer—using apt. In addition, it is useful to evaluate fuzzing coverage by leveraging tools from the `llvm` package:


```shell
apt install clang llvm
```

If the LLVM version provided by your distribution is outdated, you can install any LLVM version from [apt.llvm.org](https://apt.llvm.org/). On macOS, you can install Clang through Homebrew or Nix. On Windows, a supported version of Clang can be [installed through Visual Studio](https://learn.microsoft.com/en-us/cpp/build/clang-support-msbuild?view=msvc-170). However, we did not verify if every command and technique explained in this chapter is compatible with macOS or Windows. 

## Compile a fuzz test {#compile-a-fuzz-test}

Creating a binary that fuzzes the SUT is straightforward. The resulting binary will use the harness and the libFuzzer runtime. If using the Clang compiler, the following command produces a binary, called `fuzz`, in the current working directory:


```
clang++ -DNO_MAIN -g -O2 -fsanitize=fuzzer harness.cc main.cc -o fuzz
```


Note that you will need to recompile if you are changing the SUT or harness.

The key flag here is `-fsanitize=fuzzer`, which tells the compiler to use libFuzzer. Many things occur behind the scenes when using `-fsanitize=fuzzer`: 

* The libFuzzer runtime is linked, which provides a `main` function that runs the fuzzer.
* The [SanitizerCoverage](https://clang.llvm.org/docs/SanitizerCoverage.html) instrumentation is used to collect code coverage.
* [Built-in functions are disabled](https://github.com/llvm/llvm-project/blob/202a4c0dfb19823a0c0fc737e32d205efaffb7ff/clang/lib/Driver/SanitizerArgs.cpp#L1363-L1373) through Clang flags like `-fno-builtin-memcmp`.
* Potentially, other options are affected by enabling libFuzzer, depending on your target architecture ([search](https://github.com/search?q=repo%3Allvm%2Fllvm-project%20needsfuzzer&type=code) the LLVM codebase for indicators).

The flag `-DNO_MAIN` defines a macro that disables the default `main` function of our running example defined in the [introduction](#introduction-to-fuzzers) section. This is because libFuzzer provides its own `main` function. Depending on your project, you may need to add a similar macro if you are fuzzing a binary (this is generally not required for libraries).

We also enable debug symbols using `-g` and set the optimization level to `-O2`, which is a reasonable optimization level for fuzzing because it is likely the level used during production.

If your project depends on the GCC compiler, then consider using AFL++ together with the [gcc_plugin](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.gcc_plugin.md) instead.

## Usage {#usage}

Fuzzing can be started by running `./fuzz <corpus_dir>`. The corpus directory can be an empty directory. Ideally, you provide seed test cases. For example, if you are fuzzing a PNG library, then you may want to provide example PNG images (see [Real-world examples](#real-world-examples) for a concrete example). 

By default, libFuzzer does not continue fuzzing after a crash has been found. This behavior can be changed by appending the experimental flags `-fork=1` and `-ignore_crashes=1` (the related flags `-ignore_timeouts` and `-ignore_ooms` are enabled by default). Even though these flags are experimental, they are used widely. Therefore, we recommend running the following command to start a long-running fuzzing campaign:


```shell
./fuzz -fork=1 -ignore_crashes=1 <corpus_dir>
```

Because the example is relatively simple, an empty corpus directory is sufficient:


```shell
mkdir corpus/
```


It is also possible to omit the corpus directory. In that case, only crashes are persisted to disk and not the corpus itself. Therefore, the corpus is lost after a fuzzing campaign finishes.

From there, we can execute the fuzzer:


```shell
./fuzz corpus/
```


You will observe a crash quickly because of the simplicity of the example. The output contains statistics about the current executions per second and the corpus size.


{{< customFigure "Output of running libFuzzer. For details about this output, refer to the [libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html#output). The highlighted text shows the path to the test case that caused a crash." >}}
```text
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 3517090860
INFO: Loaded 1 modules   (9 inline 8-bit counters): 9 [0x55c248efafa0, 0x55c248efafa9),
INFO: Loaded 1 PC tables (9 PCs): 9 [0x55c248efafb0,0x55c248efb040),
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
INFO: A corpus is not provided, starting from an empty corpus
#2      INITED cov: 3 ft: 4 corp: 1/1b exec/s: 0 rss: 26Mb
#57     NEW    cov: 4 ft: 5 corp: 2/4b lim: 4 exec/s: 0 rss: 26Mb L: 3/3 MS: 5 CrossOver-ShuffleBytes-InsertByte-CrossOver-InsertByte-
#73     REDUCE cov: 4 ft: 5 corp: 2/3b lim: 4 exec/s: 0 rss: 26Mb L: 2/2 MS: 1 EraseBytes-
#16921  NEW    cov: 7 ft: 8 corp: 5/9b lim: 163 exec/s: 0 rss: 26Mb L: 2/3 MS: 2 ChangeBinInt-EraseBytes-
==11672== ERROR: libFuzzer: deadly signal

  [ ... Stacktrace ...]

SUMMARY: libFuzzer: deadly signal
MS: 4 CrossOver-CrossOver-EraseBytes-ChangeBit-; base unit: 3f786850e387550fdab836ed7e6dc881de23001b
0x61,0x62,0x63,
abc
artifact_prefix='./'; Test unit written to ./crash-a9993e364706816aba3e25717850c26c9cd0d89d
Base64: YWJj
```
{{< /customFigure >}}

At the beginning, the fuzzer prints some information about its configuration, including a seed. If you want to reproduce a libFuzzer campaign, use the command-line flag `-seed=3517090860`. Note that this will yield reproducible results only if you fuzz on a single core; with [multi-core fuzzing](#multi-core-fuzzing), sharing interesting test cases between cores becomes non-deterministic.

 

While the fuzzer is running, you will see lines printed starting with a `#`. Refer to the [libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html#output) for a more detailed explanation of the outputted data.

At the end of libFuzzer’s output, you can see the path to a file that contains the input that led to the crash. The input is also displayed encoded as hex (0x61,0x62,0x63), UTF-8 (abc), and Base64 (YWJj).

It also shows the file name of the base unit (i.e., the input that was [mutated](#the-default-fuzzing-algorithm-is-mutation-based-and-evolutionary) in order to get to the crash input). In our fuzzing example, the base unit `3f7868…` contained the string “ab.” The fuzzer mutated the string “ab” to get to the crashing input “abc.”

Note that libFuzzer does not automatically restart after a bug is found. This means that you should fix every bug you encounter before rerunning libFuzzer.

If you plan to run longer fuzzing campaigns, consider using AFL++, which continues automatically after finding a bug.


### Re-execute a test case {#re-execute-a-test-case}

A test case can be re-executed using `./fuzz <test_case>`. For example, the following command re-executes a crash:


```shell
./fuzz ./crash-a9993e364706816aba3e25717850c26c9cd0d89d
```


This helps triage found bugs. If you want to re-execute a directory of test cases without actually fuzzing (`-runs=0`), you can run:

```shell
./fuzz -runs=0 <directory>
```

### Fuzzer options {#fuzzer-options}

Several options can be set by adding command-line flags when starting `./fuzz`. (Use `-help=1` to show all of the options.)


* **-max_len=4000** The maximum length of the test input. By default, libFuzzer tries to guess this. We advise setting this at least a few times higher than the minimal input size. As a rule of thumb, we recommend finding a minimal realistic input and then doubling it. Note that larger input sizes lead to longer execution times and do not necessarily lead to a larger input space being explored.
* **-timeout=2** libFuzzer aborts the execution of a test case after n seconds. It makes sense to set this variable to something reasonably low. The goal is also to find inputs that cause the SUT to hang for an unreasonably long amount of time. For example, parsing a reasonably sized PNG image should not take longer than a few hundred milliseconds, so setting this to a few seconds is usually enough to avoid false positives. 
* **-dict=./dict.dict** This option specifies a dictionary file that guides the fuzzer and allows the fuzzer to discover interesting test cases more quickly. For more details about this, see [Dictionary fuzzing](#dictionary-fuzzing).
* **-jobs=10** Runs 10 fuzzing campaigns in sequence. See [Multi-core fuzzing](#multi-core-fuzzing) below for more information.
* **-workers=2** Runs the fuzzing campaigns defined by the `-jobs` flag using two workers. See [Multi-core fuzzing](#multi-core-fuzzing) below for more information. This flag defaults to the number of cores divided by two.
* **-fork=1 -ignore_crashes=1** Enables the libFuzzer to continue fuzzing after finding a crash. Even though the `-fork` flag is officially experimental, it is frequently used in the wild, so it is considered safe to use.
* **-close_fd_mask=3** Closes the standard input and output. This speeds up fuzzing if your SUT writes a lot of output.

## Multi-core fuzzing {#multi-core-fuzzing}

Simple support for multi-core fuzzing with libFuzzer is available. The jobs and parallelism can be controlled by the `-jobs=n` and `-workers=m` flags. By setting the jobs to, for example, 10, the fuzzer will run 10 sequential fuzzing campaigns. A new campaign starts after finding a crash. By setting the `workers` flag to 2, the jobs will be processed in parallel by using two processes. Test cases found during fuzzing are shared between fuzzing jobs. Sharing can be turned off using `-reload=0`.

The `-jobs` and `-workers` flags can be combined with the `-fork` flag, as introduced in the [Usage](#usage) section. For example, by setting the amount workers and jobs to `4` and enabling forking, libFuzzer will fuzz continuously with two processes:


```shell
./fuzz -jobs=4 -workers=4 -fork=1 -ignore_crashes=1 <corpus_dir>
```


Alternatively, the forking feature of libFuzzer can also be used:


```shell
./fuzz -fork=4 -ignore_crashes=1 <corpus_dir>
```


We recommend using the  `-jobs=4` and `-workers=4` flags instead of `-fork=4` because the forking feature is officially experimental. However, if multi-core fuzzing is a priority then switch to more capable fuzzers like AFL++, Hongfuzz, or LibAFL.

## AddressSanitizer {#addresssanitizer}

ASan helps detect memory errors that might otherwise go unnoticed. For a general introduction to ASan, refer to [AddressSanitizer](#addresssanitizer).

For instance, the following heap buffer overflow is usually not detectable without ASan; although we access the allocated buffer out of bounds, in practice, the memory we hit—which may be part of another allocation metadata—is still mapped in the process, and so the program does not crash with a segmentation fault.

{{< customFigure "main_asan.cc: Example bug detectable by ASan" >}}
```C++
void check_buf(char *buf, size_t buf_len) {
    char *last;

    if(buf_len > 0 && buf[0] == 'a') {
        if(buf_len > 1 && buf[1] == 'b') {
            if(buf_len > 2 && buf[2] == 'c') {
                last = (char*)malloc(1 * sizeof(char));
                last[0] = 'c';
                last[1] = '\0';
                printf("%s", last);
                free(last);
            }
        }
    }
}
```
{{< /customFigure >}}


To enable ASan when using libFuzzer, pass the flag `-fsanitize=address` to the compiler. You should also disable [`_FORTIFY_SOURCE`](https://www.gnu.org/software/libc/manual/html_node/Source-Fortification.html) (note: the [preceding underscore is important](https://blog.trailofbits.com/2023/04/20/typos-that-omit-security-features-and-how-to-test-for-them/)) in case your distribution enables this flag by default, which could cause false positives and negatives (because the fortified functions are not instrumented by ASan).

For example, to use ASan to find the memory corruption bug in `main_asan.cc`,  add the `-fsanitize=address` flag when compiling:

```shell
clang++ -DNO_MAIN -g -O2 -fsanitize=fuzzer -fsanitize=address harness.cc main_asan.cc -U_FORTIFY_SOURCE -o fuzz
```


You will encounter an ASan crash when running the fuzzer, as shown below.


{{< customFigure "Example ASan output. Note the first line that describes the cause of the crash: `AddressSanitizer: heap-buffer-overflow`" >}}
```text
==1276163==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020000c4ab1 at pc 0x55555568631b bp 0x7fffffffda10 sp 0x7fffffffda08
WRITE of size 1 at 0x6020000c4ab1 thread T0
    #0 0x55555568631a in check_buf(char*, unsigned long) /root/handbook/libfuzzer/main_asan.cc:13:25
    #1 0x5555556860bf in LLVMFuzzerTestOneInput /root/handbook/libfuzzer/harness.cc:7:3

(...)

(BuildId: b171fea7226b2f316f8138a7947857763d78aa1d)

0x6020000c4ab1 is located 0 bytes after 1-byte region [0x6020000c4ab0,0x6020000c4ab1)
allocated by thread T0 here:
    #0 0x555555648142 in malloc (/root/handbook/libfuzzer/fuzz+0xf4142) (BuildId: b171fea7226b2f316f8138a7947857763d78aa1d)
    #1 0x55555568621f in check_buf(char*, unsigned long) /root/handbook/libfuzzer/main_asan.cc:11:31
    #2 0x5555556860bf in LLVMFuzzerTestOneInput /root/handbook/libfuzzer/harness.cc:7:3

(...)

SUMMARY: AddressSanitizer: heap-buffer-overflow /root/handbook/libfuzzer/main_asan.cc:13:25 in check_buf(char*, unsigned long)
Shadow bytes around the buggy address:
  0x6020000c4800: fa fa fd fa fa fa fd fa fa fa fd fa fa fa fd fa
  0x6020000c4880: fa fa fd fa fa fa fd fd fa fa fd fd fa fa fd fd
  0x6020000c4900: fa fa fd fd fa fa fd fa fa fa fd fa fa fa fd fa
  0x6020000c4980: fa fa fd fa fa fa fd fa fa fa fd fa fa fa fd fa
  0x6020000c4a00: fa fa fd fa fa fa fd fa fa fa fd fa fa fa fd fa
=>0x6020000c4a80: fa fa 03 fa fa fa[01]fa fa fa fa fa fa fa fa fa
  0x6020000c4b00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x6020000c4b80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x6020000c4c00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x6020000c4c80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x6020000c4d00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==1276163==ABORTING
```
{{< /customFigure >}}




## Real-world examples {#real-world-examples}


### libpng {#libpng}

The libpng library is an open-source library used for reading and writing PNG (Portable Network Graphics) image files. Fuzzing this parser is useful because it is often used in situations where untrusted input is parsed. As a result, any bug in the parser can lead to security issues.

If you are fuzzing C projects that produce static libraries, you can follow this recipe:

1. Read the `INSTALL` file in the project’s codebase (or other appropriate documentation) and find out how to create a static library.
2. Set the compiler to Clang, and pass additional flags to the compiler during compilation.
3. Build the static library and pass the flag `-fsanitize=fuzzer-no-link` to the C compiler, which enables fuzzing-related instrumentations without linking in the fuzzing engine. The runtime, which includes the `main` symbol, is linked later when using the `-fsanitize=fuzzer` flag. The build step will create a static library, which we will refer to as `$static_library`. Additionally, pass the flag `-fsanitize=address` to enable ASan and detect memory corruption.
4. Find the compiled static library from step 3 and call: `clang++ -fsanitize=fuzzer -fsanitize=address $static_library harness.cc -o fuzz`.
5. You can start fuzzing by calling `./fuzz`.

Let’s go through these instructions for the well-known libpng library. First, we get the source code:


```shell
curl -L -O https://downloads.sourceforge.net/project/libpng/libpng16/1.6.37/libpng-1.6.37.tar.xz
tar xf libpng-1.6.37.tar.xz
cd libpng-1.6.37/
```


Before we can compile libpng, we have to install dependencies for it:

```shell
apt install zlib1g-dev
```

Next, we configure and compile libpng as a static library without linking libFuzzer by using the `-fsanitize=fuzzer-no-link` flag. Because we are building a static library, we are not yet linking a binary.

```shell
export CC=clang CFLAGS="-fsanitize=fuzzer-no-link -fsanitize=address" # Set C compiler and the flag for fuzzing
export CXX=clang++ CXXFLAGS="$CFLAGS" # Set C++ compiler and use C flags
./configure --enable-shared=no # Configure to compile a static library
	make # Run compilation
```

By default, the configuration script sets the optimization level to `-O2`, which is what we recommend in the [Compile a Fuzz test section](#compile-a-fuzz-test).

Note that, depending on your fuzzing environment, you may need to install missing dependencies such that the compilation succeeds. For example, on a plain installation of Ubuntu, you may need to install the package `zlib1g-dev` as described above.

Next, we download a harness from GitHub. Usually, you would have to write a harness yourself. However, for this example, an existing one from the libpng authors suffices.


```shell
curl -O https://raw.githubusercontent.com/glennrp/libpng/f8e5fa92b0e37ab597616f554bee254157998227/contrib/oss-fuzz/libpng_read_fuzzer.cc
```


From there, we prepare a corpus to simplify the task of finding bugs for the fuzzer. This is an optional step because libFuzzer can start from an empty corpus. However, it is helpful to prepare a corpus with real-world inputs so that the fuzzer does not start from scratch. Starting from a single valid PNG file, as shown below, already significantly improves fuzzing effectiveness.


```shell
mkdir corpus/
curl -o corpus/input.png https://raw.githubusercontent.com/glennrp/libpng/acfd50ae0ba3198ad734e5d4dec2b05341e50924/contrib/pngsuite/iftp1n3p08.png
```


We also download a [dictionary](#dictionary-fuzzing) for the PNG format to better guide the fuzzer. A dictionary provides the fuzzer with some initial clues about the file format, such as which magic bytes PNG uses.


```
curl -O https://raw.githubusercontent.com/glennrp/libpng/2fff013a6935967960a5ae626fc21432807933dd/contrib/oss-fuzz/png.dict
```


Finally, we link together the instrumented libpng, the harness, and the libFuzzer runtime.


```shell
$CXX -fsanitize=fuzzer -fsanitize=address libpng_read_fuzzer.cc .libs/libpng16.a -lz -o fuzz
```


The fuzzing campaign can be launched by running:


```shell
./fuzz -close_fd_mask=3 -dict=./png.dict corpus/
```


### CMake-based project {#cmake-based-project}

Let’s assume we are using CMake to build the program mentioned in the [introduction](#introduction-to-fuzzers). We add a CMake target that builds the `main.cc` and `harness.cc` and links the target together with libFuzzer. Note that we are excluding the main function through the `NO_MAIN` flag; otherwise, the program would have two main functions, because libFuzzer also provides one.

{{< customFigure "CMakeLists: Example CMake file for compiling a program and a fuzzer for it" >}}
```cmake
project(BuggyProgram)
cmake_minimum_required(VERSION 3.0)

add_executable(buggy_program main.cc)

add_executable(fuzz main.cc harness.cc)
target_compile_definitions(fuzz PRIVATE NO_MAIN=1)
target_compile_options(fuzz PRIVATE -g -O2 -fsanitize=fuzzer)
target_link_libraries(fuzz -fsanitize=fuzzer)
```

{{< /customFigure >}}


The project can be build using the following commands:


```shell
cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ .
cmake --build .
```

The fuzzing campaign can be launched by running `./fuzz`.


## Additional resources {#additional-resources}

* [Clang libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html)
* [Tutorial on libFuzzer by Google](https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md)
