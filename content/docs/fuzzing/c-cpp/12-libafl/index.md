---
title: "LibAFL"
slug: libafl
weight: 3
---


# LibAFL {#libafl}

The [LibAFL](https://github.com/AFLplusplus/LibAFL/) fuzzer implements features from [AFL](https://github.com/google/AFL)\-based fuzzers like AFL++. Similarly to AFL++, LibAFL provides better fuzzing performance and more advanced features over libFuzzer. However, with LibAFL, all functionality is provided in a modular and customizable way—in fact, LibAFL is a library that can be used to implement custom fuzzers. Because LibAFL is a library, there is no single-line command to install LibAFL like there is with libFuzzer (`apt install clang`) and AFL++ (`apt install afl++`). However, LibAFL can be used as a drop-in replacement for libFuzzer. Another way to use LibAFL is to create a Rust project and then use the library to create a fuzzer. This section about LibAFL covers both approaches: **1\) libFuzzer drop-in** and **2\) LibAFL as Rust library**.

{{< fuzzing/intro-os >}}

## Setup {#setup}

First, install LibAFL's two major dependencies: Clang/LLVM and Rust. If your system has a version of Clang greater than 14, you may install it directly from the distribution.

```shell
apt install clang
```

If you want to use a specific version of Clang, then install Clang through [apt.llvm.org](https://apt.llvm.org/):

```shell
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 15
```

Next, we need to tell Rust to use this version of Clang. Rust depends on the linker `cc` being available on the path. We can set the `RUSTFLAGS` variable to change the version of the linker binary:

```shell
export RUSTFLAGS="-C linker=/usr/bin/clang-15"
```

Also, the [cc crate](https://docs.rs/cc/latest/cc/) depends on the `cc` program. We can change the compiler used in that crate by setting the `CC` and `CXX` variables:

```shell
export CC="clang-15"
export CXX="clang++-15"
```

Please note that you may want to [unset](https://man7.org/linux/man-pages/man1/unset.1p.html) these environment variables after compiling the LibAFL Rust project, as they may interfere with compiling your SUT.

The LLVM version requirement can [change without warning](https://github.com/AFLplusplus/LibAFL/pull/2046/files). At the time of writing, you should use LLVM 15 through 18\. Refer to the [README](https://github.com/AFLplusplus/LibAFL/blob/main/README.md) if in doubt or if you experience problems.

Next, install Rust using [rustup](https://rustup.rs/):

```shell
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

You may need to install additional system dependencies:

```shell
apt install libssl-dev pkg-config
```

## LibAFL as libFuzzer drop-in replacement {#libafl-as-libfuzzer-drop-in-replacement}

The libFuzzer compatibility layer depends on a nightly Rust version. Install the latest nightly version, including LLVM tools:

```shell
rustup toolchain install nightly --component llvm-tools
```

Next, clone LibAFL's source code and build the libFuzzer drop-in replacement. Note that we are using the main branch here, not a specific version. While there are releases of LibAFL, the fuzzer is still in active development, so it is generally advisable to use the main branch.

```shell
git clone https://github.com/AFLplusplus/LibAFL
cd LibAFL/libafl_libfuzzer_runtime
./build.sh
```

We now have a static binary called `libFuzzer.a` in the current working directory.

### Compile a fuzz test {#compile-a-fuzz-test-libfuzzer}

Similarly to the [libFuzzer section]({{% relref "10-libfuzzer" %}}), we can now compile our `harness.cc` and `main.cc` from the [introduction]({{% relref "fuzzing#introduction-to-fuzzers" %}}). Instead of using the default libFuzzer with the flag `-fsanitize=fuzzer`, we are providing our own libFuzzer runtime. Make sure that the `harness.cc` and `main.cc` are in your working directory.

```shell
clang++ -DNO_MAIN -g -O2 -fsanitize=fuzzer-no-link libFuzzer.a harness.cc main.cc -o fuzz
```

Note that you will need to recompile if you are changing the SUT or harness.

The flag `-fsanitize=fuzzer-no-link` enables several compiler options, but does not link in the fuzzer runtime as it would if you use `-fsanitize=fuzzer`. For more details about `-DNO_MAIN`, `-g`, or `-O2`, refer to the [libFuzzer section]({{% relref "10-libfuzzer#compile-a-fuzz-test" %}}).

### Usage

Start fuzzing by running `./fuzz <corpus_dir>`, where the corpus directory can be an empty directory. Ideally, you provide seed test cases, like small PNG images if you are fuzzing a PNG parser.

Just like classical libFuzzer, the drop-in replacement also stops fuzzing after finding a first crash. This can be changed by using the `-fork=1` and `-ignore_crashes=1` flags, which, compared to the default libFuzzer implementation, are not experimental in LibAFL. The `-fork=1` flag makes LibAFL fork the process and restart child processes using [`SimpleRestartingEventManager`](https://docs.rs/libafl/0.12.0/libafl/events/simple/struct.SimpleRestartingEventManager.html). Note that the flags `-fork` and `-jobs` are synonyms in LibAFL. If using a value larger than one for these flags, then the more capable [`LlmpRestartingEventManager`](https://docs.rs/libafl/0.12.0/libafl/events/llmp/struct.LlmpRestartingEventManager.html), which supports multi-processing, is used. The following command is recommended for long-running fuzzing campaigns:

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

{{< customFigure "Output of running libFuzzer." >}}
```text
[UserStats   #0]  (GLOBAL) run time: 0h-0m-0s, clients: 1, corpus: 0, objectives: 0, executions: 0, exec/sec: 0.000, edges: 33.333%
                  (CLIENT) corpus: 0, objectives: 0, executions: 0, exec/sec: 0.000, edges: 3/9 (33%)
[UserStats   #0]  (GLOBAL) run time: 0h-0m-0s, clients: 1, corpus: 0, objectives: 0, executions: 0, exec/sec: 0.000, edges: 33.333%, size_edges: 33.333%
                  (CLIENT) corpus: 0, objectives: 0, executions: 0, exec/sec: 0.000, edges: 3/9 (33%), size_edges: 3/9 (33%)
[Testcase    #0]  (GLOBAL) run time: 0h-0m-0s, clients: 1, corpus: 1, objectives: 0, executions: 1, exec/sec: 0.000, edges: 33.333%, size_edges: 33.333%
                  (CLIENT) corpus: 1, objectives: 0, executions: 1, exec/sec: 0.000, edges: 3/9 (33%), size_edges: 3/9 (33%)
We imported 1 inputs from disk.
[UserStats   #0]  (GLOBAL) run time: 0h-0m-0s, clients: 1, corpus: 1, objectives: 0, executions: 1, exec/sec: 0.000, stability: 100.000%, edges: 33.333%, size_edges: 33.333%
                  (CLIENT) corpus: 1, objectives: 0, executions: 1, exec/sec: 0.000, stability: 9/9 (100%), edges: 3/9 (33%), size_edges: 3/9 (33%)
[UserStats   #0]  (GLOBAL) run time: 0h-0m-0s, clients: 1, corpus: 1, objectives: 0, executions: 1, exec/sec: 0.000, edges: 44.444%, size_edges: 33.333%, stability: 100.000%
                  (CLIENT) corpus: 1, objectives: 0, executions: 1, exec/sec: 0.000, edges: 4/9 (44%), size_edges: 3/9 (33%), stability: 9/9 (100%)
[UserStats   #0]  (GLOBAL) run time: 0h-0m-0s, clients: 1, corpus: 1, objectives: 0, executions: 1, exec/sec: 0.000, edges: 44.444%, size_edges: 44.444%, stability: 100.000%
                  (CLIENT) corpus: 1, objectives: 0, executions: 1, exec/sec: 0.000, edges: 4/9 (44%), size_edges: 4/9 (44%), stability: 9/9 (100%)
[Testcase    #0]  (GLOBAL) run time: 0h-0m-0s, clients: 1, corpus: 2, objectives: 0, executions: 30, exec/sec: 0.000, edges: 44.444%, size_edges: 44.444%, stability: 100.000%
                  (CLIENT) corpus: 2, objectives: 0, executions: 30, exec/sec: 0.000, edges: 4/9 (44%), size_edges: 4/9 (44%), stability: 9/9 (100%)
[UserStats   #0]  (GLOBAL) run time: 0h-0m-0s, clients: 1, corpus: 2, objectives: 0, executions: 30, exec/sec: 0.000, edges: 55.556%, size_edges: 44.444%, stability: 100.000%
                  (CLIENT) corpus: 2, objectives: 0, executions: 30, exec/sec: 0.000, edges: 5/9 (55%), size_edges: 4/9 (44%), stability: 9/9 (100%)
[UserStats   #0]  (GLOBAL) run time: 0h-0m-0s, clients: 1, corpus: 2, objectives: 0, executions: 30, exec/sec: 0.000, edges: 55.556%, size_edges: 55.556%, stability: 100.000%
                  (CLIENT) corpus: 2, objectives: 0, executions: 30, exec/sec: 0.000, edges: 5/9 (55%), size_edges: 5/9 (55%), stability: 9/9 (100%)
[Testcase    #0]  (GLOBAL) run time: 0h-0m-0s, clients: 1, corpus: 3, objectives: 0, executions: 354, exec/sec: 0.000, edges: 55.556%, size_edges: 55.556%, stability: 100.000%
                  (CLIENT) corpus: 3, objectives: 0, executions: 354, exec/sec: 0.000, edges: 5/9 (55%), size_edges: 5/9 (55%), stability: 9/9 (100%)
[2024-06-06T14:39:11Z ERROR libafl::executors::hooks::unix::unix_signal_handler] Crashed with SIGABRT
[2024-06-06T14:39:11Z ERROR libafl::executors::hooks::unix::unix_signal_handler] Child crashed!
[2024-06-06T14:39:11Z ERROR libafl::executors::hooks::unix::unix_signal_handler] input: "8ac0f08adee16e49"
    ━━━━━━━━━━━━ CRASH ━━━━━━━━━━━━━━━━
    Received signal SIGABRT at 0x00761319e969fc, fault address: 0x00000000000000
    ━━━━━━━━━━━━ REGISTERS ━━━━━━━━━━━━
    r8 : 0x007ffff7d61830, r9 : 0x00000000000000, r10: 0x00000000000008, r11: 0x00000000000246,
    r12: 0x00000000000006, r13: 0x00000000000016, r14: 0x00761316080cc2, r15: 0x00000000000025,
    rdi: 0x00000000005f2c, rsi: 0x00000000005f2c, rbp: 0x00000000005f2c, rbx: 0x0076131a441940,
    rdx: 0x00000000000006, rax: 0x00000000000000, rcx: 0x00761319e969fc, rsp: 0x007ffff7d61760,
    rip: 0x00761319e969fc, efl: 0x00000000000246,
    ━━━━━━━━━━━━ BACKTRACE ━━━━━━━━━━━
       0: libafl_bolts::minibsod::generate_minibsod
                 at libafl_bolts/src/minibsod.rs:1080:30
       1: libafl::executors::hooks::unix::unix_signal_handler::inproc_crash_handler
                 at libafl/src/executors/hooks/unix.rs:208:32
       2: libafl::executors::hooks::unix::unix_signal_handler::<impl libafl_bolts::os::unix_signals::Handler for libafl::executors::hooks::inprocess::InProcessExecutorHandlerData>::handle
       3: libafl_bolts::os::unix_signals::handle_signal
                 at libafl_bolts/src/os/unix_signals.rs:436:5
       4: <unknown>
       5: pthread_kill
       6: gsignal
       7: abort
       8: _Z9check_bufPcm
                 at libafl_libfuzzer/libafl_libfuzzer_runtime/main.cc:8:17
       9: LLVMFuzzerTestOneInput
                 at libafl_libfuzzer/libafl_libfuzzer_runtime/harness.cc:7:3
      10: libafl_libfuzzer_test_one_input
                 at

...

libafl_libfuzzer/libafl_libfuzzer_runtime/src/lib.rs:500:9
      17: LLVMFuzzerRunDriver
                 at libafl_libfuzzer/libafl_libfuzzer_runtime/src/lib.rs:641:32
      18: main
                 at libafl_targets/src/libfuzzer.c:37:10
      19: <unknown>
      20: __libc_start_main
      21: _start

    ━━━━━━━━━━━━ MAPS ━━━━━━━━━━━━
    7fff7000-8fff7000 rw-p 00000000 00:00 0
    8fff7000-2008fff7000 ---p 00000000 00:00 0
    2008fff7000-10007fff8000 rw-p 00000000 00:00 0
    5596786b1000-559678764000 r--p 00000000 08:01 524035                     libafl_libfuzzer/libafl_libfuzzer_runtime/fuzz
    559678764000-559678d69000 r-xp 000b3000 08:01 524035

...

    76131a4a8000-76131a4aa000 rw-p 00039000 08:01 16134                      /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    7ffff7d46000-7ffff7d67000 rw-p 00000000 00:00 0                          [stack]
    7ffff7dea000-7ffff7dee000 r--p 00000000 00:00 0                          [vvar]
    7ffff7dee000-7ffff7df0000 r-xp 00000000 00:00 0                          [vdso]
    ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]

[Objective   #0]  (GLOBAL) run time: 0h-0m-0s, clients: 1, corpus: 3, objectives: 1, executions: 548, exec/sec: 0.000, edges: 55.556%, size_edges: 55.556%, stability: 100.000%
                  (CLIENT) corpus: 3, objectives: 1, executions: 548, exec/sec: 0.000, edges: 5/9 (55%), size_edges: 5/9 (55%), stability: 9/9 (100%)
```
{{< /customFigure >}}

Lines starting with `[UserStats #0]` or `[Testcase #0]` correspond to events being logged. The `UserStats` event (also sometimes called the `Client Heartbeat` event) is regularly issued to provide updates on the current fuzzing campaign. The `Testcase` event is issued whenever a new test case is discovered. Note that it is normal to occasionally not see new logs for at least some time if no new test cases or crashes are found.

Alongside the events, additional information is printed, such as how long the fuzzer is already running (`run time`), how many parallel processes are fuzzing  (`clients`), how many corpus entries exist (`corpus`), how many crashes or out-of-memory bugs have been found (`objectives`), how many times the SUT has been invoked (`executions`), and the current executions per second (`exec/sec`). If you are fuzzing on multiple cores (using `-fork` or `-jobs` flags), then you will see statistics being printed for each individual fuzzing process as well as global aggregated statistics.

{{< customFigure "Example of statistics printed by the libFuzzer mode" >}}
```text
[UserStats   #0]  (GLOBAL) run time: 0h-0m-0s, clients: 1, corpus: 0, objectives: 0, executions: 0, exec/sec: 0.000, edges: 100.000%, size_edges: 100.000%
                  (CLIENT) corpus: 0, objectives: 0, executions: 0, exec/sec: 0.000, edges: 2/2 (100%), size_edges: 2/2 (100%)
```
{{< /customFigure >}}

The flag `-tui=1` enables a graphical text-based statistics view. It also implicitly enables fuzzing in a forked child process instead of the main process. The logic for forking is implemented in the [fuzz](https://github.com/AFLplusplus/LibAFL/blob/c7207dceb05695f9beca297b220198c9dd78cccc/libafl_libfuzzer/runtime/src/fuzz.rs#L193-L228) function in LibAFL.

{{< resourceFigure "libafl.png" >}}
LibAFL TUI
{{< /resourceFigure >}}


## LibAFL as Rust library

The more flexible way to use LibAFL is as a library. As the name LibAFL suggests, the project is primarily a fuzzer. The method using the libFuzzer compatibility layer described in the previous section is not part of the core library and is mostly a very easy way to get started. If you want to get the most out of LibAFL, you should consider implementing your own fuzzer using the library.

### Creating a LibAFL-based fuzzer

This section aims to compile the harness `harness.cc`, the target `main.cc`, and our custom-configured LibAFL fuzzer runtime. We will then bootstrap a new Rust project that uses LibAFL. Then, the resulting binary is linked to our harness and target program.

Create a new Rust project called appsec\_guide and add the LibAFL dependency.

```shell
cargo init --lib appsec_guide
cd appsec_guide
cargo add libafl@0.13 libafl_targets@0.13 libafl_bolts@0.13 libafl_cc@0.13 --features "libafl_targets@0.13/libfuzzer,libafl_targets@0.13/sancov_pcguard_hitcounts"
```

The feature selection is an essential part of getting your LibAFL fuzzer right:

* `libafl_targets/libfuzzer`:  Adds several helper functions that mimic the behavior of libFuzzer in a lightweight way. For instance, it provides a wrapper function to call `LLVMFuzzerTestOneInput` by calling `libafl_targets::libfuzzer_test_one_input`. It also [defines the main function](https://github.com/AFLplusplus/LibAFL/blob/571c4c111e99924cf4ed5580622a018b3dbb21c9/libafl_targets/src/libfuzzer.c#L35-L46) that calls the `libafl_main` function we are going to define further below.
* `libafl_targets/sancov_pcguard_hitcounts`: Adds a global map that maintains coverage statistics. It also defines functions that can be used by the [LLVM coverage instrumentation](https://clang.llvm.org/docs/SourceBasedCodeCoverage.html) to populate the coverage map.

{{< hint info >}}
PRO TIP: Previously, we discussed that LibAFL is still a work in progress. If you instead want to use a specific commit of LibAFL, use the following command:
```shell
cargo add --git https://github.com/AFLplusplus/LibAFL --rev 2356ba575 libafl libafl_targets libafl_bolts libafl_cc --features "libafl_targets/libfuzzer,libafl_targets/sancov_pcguard_hitcounts"
```
Please note that you might need to update Rust to the latest version, as a [bug](https://github.com/rust-lang/cargo/issues/13121) has been discovered that results in an error in the above command.
{{< /hint >}}

Our example fuzzer will use command-line options. Therefore, we need to add the clap dependency:

```shell
cargo add clap@4 --features "derive"
```

The library crate should be compiled into a static library. To achieve this, we need to set the `crate-type` to `staticlib` in the `Cargo.toml` file:

{{< customFigure "Final `Cargo.toml` file of the fuzzer" >}}
```toml
[package]
name = "appsec_guide"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["staticlib"]

[dependencies]
clap = { version = "4", features = ["derive"] }
libafl = "0.13.1"
libafl_bolts = "0.13.1"
libafl_cc = "0.13.1"
libafl_targets = { version = "0.13.1", features = ["libfuzzer", "sancov_pcguard_hitcounts"] }
```
{{< /customFigure >}}

After setting up the basic project, clear the `src/lib.rs` file. The [full source code](https://github.com/trailofbits/testing-handbook/tree/main/materials/fuzzing/libafl/appsec_guide) for the following fuzzer can be found on GitHub.

The following figure showcases a basic skeleton for a LibAFL fuzzer. The skeleton includes imports, a struct including parsed command line options, and the `libafl_main` function. Within the `libafl_main` function, we parse the command-line options, define the closure `run_client`, and finally set up everything using a LibAFL [Launcher](https://docs.rs/libafl/0.13.1/libafl/events/launcher/index.html). To set up the launcher instance, we define several options:

* `.shmem_provider()` sets a shared-memory provider. Shared memory is used to synchronize fuzzing clients. The implementation is chosen based on the operating system.
* `.configuration()` gives the fuzzer a name, which in this case is “default.”
* `.monitor()` sets the monitor records aggregated statistics in a TOML file called `./fuzzer_stats.toml` and logs current statistics to the standard output.
* `.run_client()` defines the lambda that creates the fuzzer and clients.
* `.cores()` defines which and how many cores are used. Generally, you use the `Cores::from_cmdline` function to create a `Cores` instance from a string. For example, the string “0” creates a single client fuzzer that runs on the core with ID `0`. The string ”0,8-15” launches nine clients that run on core `0` and on the cores ranging from ID 8 until 15 (inclusive).
* `.broker_port()` sets the port that the main broker process is using. Initial communication between a client and the main broker process happens over TCP.
* `.remote_broker_addr()` can be used to set a broker process to connect to in case one already exists. Otherwise, this can be set to `None`.
* `.stdout_file()` redirects the standard output of the SUT. You may want to set this to `/dev/null` if the output does not matter and the output is noisy. We comment this option here, as it may hide issues with the fuzzer because it also hides output printed in the `run_client` closure.

{{< customFigure "Skeleton for a LibAFL fuzzer. [Full source code](https://github.com/trailofbits/testing-handbook/blob/main/materials/fuzzing/libafl/appsec_guide/src/lib.rs) can be found in the GitHub repository of the Testing Handbook." >}}
```rust
use libafl::{
    ...
};
use libafl_bolts::{
    ...
};
use libafl_targets::{libfuzzer_initialize, libfuzzer_test_one_input, std_edges_map_observer};
...

/// The commandline args this fuzzer accepts
#[derive(Debug, Parser)]
#[command(
    name = "appsec_guide",
    about = "A libfuzzer-like fuzzer with llmp-multithreading support and a launcher"
)]
struct Opt {
    ...
}

/// The main fn, `no_mangle` as it is a C symbol
#[no_mangle]
pub extern "C" fn libafl_main() {
    let opt = Opt::parse();

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );

    let mut run_client = |state: Option<_>, mut restarting_mgr, _core_id| {

       ...

       Ok(())
    };

    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    let monitor = OnDiskTOMLMonitor::new(
        "./fuzzer_stats.toml",
        MultiMonitor::new(|s| println!("{s}")),
    );

    let broker_port = opt.broker_port;
    let cores = opt.cores;

    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .configuration(EventConfig::from_name("default"))
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&cores)
        .broker_port(broker_port)
        .remote_broker_addr(opt.remote_broker_addr)
//     .stdout_file(Some("/dev/null"))
        .build()
        .launch()
    {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
        Err(err) => panic!("Failed to run launcher: {err:?}"),
    }
}
```
{{< /customFigure >}}

The skeleton code does not yet fuzz any target. The actual fuzzer setup is handled in the `run_client` closure; because LibAFL natively supports multiprocessing, it can handle multiple clients by executing the closure multiple times.

The following figures show how to set up a fuzzer client in the `run_client` closure step by step.

{{< customFigure "Setup of fuzzer feedback. [Full source code](https://github.com/trailofbits/testing-handbook/blob/main/materials/fuzzing/libafl/appsec_guide/src/lib.rs)" >}}
```rust
// Create an observation channel using the coverage map
let edges_observer =
    HitcountsMapObserver::new(unsafe { std_edges_map_observer("edges") }).track_indices();

// Create an observation channel to keep track of the execution time
let time_observer = TimeObserver::new("time");

// Feedback to rate the interestingness of an input
// This one is composed of two feedbacks in OR
let mut feedback = feedback_or!(
    // New maximization map feedback linked to the edges observer
    MaxMapFeedback::new(&edges_observer),
    // Time feedback
    TimeFeedback::new(&time_observer)
);
```
{{< /customFigure >}}

The fuzzer we are creating is guided by coverage and time. Coverage is gathered from a global map. After every execution of the harness, LibAFL uses data from the map to determine whether coverage has increased and how many new edges have been discovered. The code above first defines two observers, which are then used as feedback, essentially defining whether an execution of a test case has been interesting. The `feedback_or!` macro specifies that either feedback suffices to deem the test case interesting.

The observers will become important again when setting up the scheduler and executor. Note here that the `edges_observer` can track indices (see the call to the `track_indices` function).

{{< customFigure "Setup of the fuzzer objective. [Full source code](https://github.com/trailofbits/testing-handbook/blob/main/materials/fuzzing/libafl/appsec_guide/src/lib.rs)" >}}
```rust
// A feedback to choose if an input is a solution or not
let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());
```
{{< /customFigure >}}

The fuzzer not only needs feedback to guide the fuzzer, but also to establish a goal. This is defined similarly to feedback; in this instance, the fuzzer has the goal of finding crashing inputs and inputs that time out. Note that neither type of feedback requires an observer because the core LibAFL engine natively supports both types. By using the `feedback_or_fast!` macro instead of `feedback_or!`, the timeout feedback is not evaluated if a crash occurs.

{{< customFigure "Setup of the fuzzer state. [Full source code](https://github.com/trailofbits/testing-handbook/blob/main/materials/fuzzing/libafl/appsec_guide/src/lib.rs)" >}}
```rust
// If not restarting, create a State from scratch
let mut state = state.unwrap_or_else(|| {
    StdState::new(
        // RNG
        StdRand::new(),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryCorpus::new(),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(&opt.output).unwrap(),
        // States of the feedbacks.
        // The feedbacks can report the data that should persist in the State.
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    )
    .unwrap()
});

println!("We're a client, let's fuzz :)");
```
{{< /customFigure >}}

Next, we either create a new fuzzer state or, if we are restarting this client after a crash, reuse an existing state. When creating a new state, we can specify a random number generator (RNG), the corpora, and include the feedback definition. `StdRand` is sufficient for most applications for the RNG. The RNG is used to mutate test cases or generate new ones.

The fuzzer uses two corpora: one for storing interesting test cases and one for storing test cases that fulfill the objective (test cases that time out or crash). The current example uses an `InMemoryCorpus` for test cases, which means that discovered test cases that increase coverage will be lost after a restart. `InMemoryCorpus` can be replaced with an [`InMemoryOnDiskCorpus`](https://docs.rs/libafl/0.13.1/libafl/corpus/inmemory_ondisk/struct.InMemoryOnDiskCorpus.html) to keep test cases primarily in memory while also storing a backup on disk.


{{< customFigure "Setup of mutations and the mutational stage. [Full source code](https://github.com/trailofbits/testing-handbook/blob/main/materials/fuzzing/libafl/appsec_guide/src/lib.rs)" >}}
```rust
// Setup a basic mutator with a mutational stage
let mutator = StdScheduledMutator::new(havoc_mutations());
let mut stages = tuple_list!(StdMutationalStage::new(mutator));
```
{{< /customFigure >}}

From here, we define the mutations the fuzzer should use. We use the havoc mutations that are known from fuzzers like AFL++. LibAFL has the concept of stages that are executed for every test case.


{{< customFigure "Setup of the scheduling algorithm. [Full source code](https://github.com/trailofbits/testing-handbook/blob/main/materials/fuzzing/libafl/appsec_guide/src/lib.rs)" >}}
```rust
// A minimization+queue policy to get test cases from the corpus
let scheduler =
    IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());
```
{{< /customFigure >}}

Scheduling which test cases to mutate and execute is an important part of fuzzing. The simplest strategy is to pick a random test case that is implemented in [`RandScheduler`](https://docs.rs/libafl/0.13.1/libafl/schedulers/struct.RandScheduler.html). The above code defines a schedule that picks favorable test cases in a queue-like fashion. To achieve this, the fuzzer maintains a state that describes which test cases are short and take a short time to execute. Internally, LibAFL attaches metadata to the fuzzer state ([`TopRatedsMetadata`](https://docs.rs/libafl/latest/libafl/schedulers/minimizer/struct.TopRatedsMetadata.html)) and test cases ([`IsFavoredMetadata`](https://docs.rs/libafl/0.13.1/libafl/schedulers/minimizer/struct.IsFavoredMetadata.html) and [`MapIndexesMetadata`](https://docs.rs/libafl/latest/libafl/feedbacks/map/struct.MapIndexesMetadata.html)). The important part to note here is that this specific scheduler depends on having an observer who can track indices. This is true for our `edges_observer` because we used the `track_indices` function when setting it up.
For more information, refer to the [source code](https://github.com/AFLplusplus/LibAFL/blob/571c4c111e99924cf4ed5580622a018b3dbb21c9/libafl/src/schedulers/minimizer.rs).


{{< customFigure "Setup of the fuzzer based on the scheduler, feedback and objective. [Full source code](https://github.com/trailofbits/testing-handbook/blob/main/materials/fuzzing/libafl/appsec_guide/src/lib.rs)" >}}
```rust
// A fuzzer with a corpus scheduler, feedback, and objective
let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
```
{{< /customFigure >}}

We are now ready to set up the fuzzer and link the scheduler with the feedback and objective.


{{< customFigure "Setup of the harness and the executor. [Full source code](https://github.com/trailofbits/testing-handbook/blob/main/materials/fuzzing/libafl/appsec_guide/src/lib.rs)" >}}
```rust
// The wrapped harness function, calling out to the LLVM-style harness
let mut harness = |input: &BytesInput| {
    let target = input.target_bytes();
    let buf = target.as_slice();
    libfuzzer_test_one_input(buf);
    ExitKind::Ok
};

let mut executor = InProcessExecutor::with_timeout(
    &mut harness,
    tuple_list!(edges_observer, time_observer),
    &mut fuzzer,
    &mut state,
    &mut restarting_mgr,
    opt.timeout,
)?;
```
{{< /customFigure >}}

A simple but important step is to define the harness. The harness above calls `libfuzzer_test_one_input`, which is a wrapper around the `LLVMFuzzerTestOneInput` function. Our harness is libFuzzer compatible, so this function is ideal for our use case.


{{< customFigure "Optionally, call the LLVMFuzzerInitialize function to initialize the harness. [Full source code](https://github.com/trailofbits/testing-handbook/blob/main/materials/fuzzing/libafl/appsec_guide/src/lib.rs)" >}}
```rust
// The actual target run starts here.
// Call LLVMFUzzerInitialize() if present.
let args: Vec<String> = env::args().collect();
if libfuzzer_initialize(&args) == -1 {
    println!("Warning: LLVMFuzzerInitialize failed with -1");
}
```
{{< /customFigure >}}

We are not currently using the `LLVMFuzzerInitialize` function in our harness, but it is a good practice to call this function if it exists in case the harness requires initialization. LibAFL links and calls it if it exists; otherwise, nothing happens.


{{< customFigure "Start the fuzzing by loading initial test cases and then looping forever. [Full source code](https://github.com/trailofbits/testing-handbook/blob/main/materials/fuzzing/libafl/appsec_guide/src/lib.rs)" >}}
```rust
// In case the corpus is empty (on first run), reset
if state.must_load_initial_inputs() {
    state
        .load_initial_inputs(&mut fuzzer, &mut executor, &mut restarting_mgr, &opt.input)
        .unwrap_or_else(|_| panic!("Failed to load initial corpus at {:?}", &opt.input));
    println!("We imported {} inputs from disk.", state.corpus().count());
}

fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut restarting_mgr)?;
```
{{< /customFigure >}}

The final setup is to load the initial corpus when the client starts for the first time and then start the fuzzing loop by calling the `fuzz_loop` function. An important thing to note here is that the fuzzer will not start and run if none of the test cases in the corpus are interesting, which could be the case if the coverage instrumentation of the target fails.

We can now build the fuzzer:

```shell
cargo build --release
```

The resulting binary is located at `target/release/libappsec_guide.a`.

### Compile a fuzz test {#compile-a-fuzz-test-rust}

In the previous section, we created a custom LibAFL-based fuzzer. Now we are going to link the compiled fuzzer runtime, called `libappsec_guide.a`, to our harness and target. We are reusing the `harness.cc` and `main.cc` from the [introduction]({{% relref "fuzzing#introduction-to-fuzzers" %}}). The resulting binary will use the harness and the libFuzzer runtime.

This section presents two options for creating the final binary. The first one shows how to link in a verbose way: it details all LLVM features that are required to create the fuzzer. The second option is the standard one and is recommended for new users of LibAFL. However, it is important to understand what happens behind the scenes, so we will start with the verbose way.

#### Verbose instrumentation and linking

If using the Clang compiler, the following command produces a binary called `fuzz` in the current working directory:

```shell
clang++-15 -DNO_MAIN -g -O2 -fsanitize-coverage=trace-pc-guard -fsanitize=address -Wl,--whole-archive target/release/libappsec_guide.a -Wl,--no-whole-archive main.cc harness.cc -o fuzz
```

Here are the descriptions for each argument:

* `clang++-15`: This is the compiler used for instrumenting the SUT. To use a specific version of LLVM, use, for example, `clang++-15` instead of `clang++`.
* `-DNO_MAIN -g -O2`: These arguments prevent compiling of the `main` function for main.cc, add debug symbols and use the most common production optimization level.
* `-fsanitize-coverage=trace-pc-guard`: This argument enables LLVM coverage instrumentation. This is required, or else the fuzzer won’t get any feedback and won’t add any test cases to the corpus.
* `-fsanitize=address`: This argument enables AddressSanitizer.
* `-Wl,--whole-archive target/release/libappsec_guide.a -Wl,--no-whole-archive`: These arguments link the complete fuzzer runtime. Without `--whole-archive`, the linker will discard the fuzzing runtime completely and set the [`libafl_main` external symbol](https://github.com/AFLplusplus/LibAFL/blob/571c4c111e99924cf4ed5580622a018b3dbb21c9/libafl_targets/src/libfuzzer.c#L29) to null. This behavior is linked to weak symbols and is also described in this [StackOverflow issue](https://stackoverflow.com/questions/2627839/weak-linking-with-static-libraries). The other workaround is to add `-u libafl_main` instead of using the whole archive flags.
* `main.cc harness.cc`: These are the SUT and harness to compile, instrument, and link.
* `-o fuzz` \- This is the argument for the output binary.

The resulting binary `fuzz` can now be executed to start the fuzzing campaign.

#### Standard linking

The standard way in LibAFL to link the runtime, SUT, and harness is to create a compiler wrapper. When compiling the SUT and harness, instead of using the Clang directly from LLVM, we invoke a custom wrapper that parses the compilation flags; modifies, injects, or removes flags; and then invokes the LLVM Clang.

The LibAFL project provides a library called `libafl_cc` which allows us to easily create wrappers. The following figure shows a compiler wrapper. Add this as `libafl_cc.rs` to your Rust crate under `src/bin` (the default path for Rust binaries).


{{< customFigure "src/bin/libafl_cc.rs: Compiler wrapper binary for LibAFL. [Full source code](https://github.com/trailofbits/testing-handbook/blob/main/materials/fuzzing/libafl/appsec_guide/src/bin/libafl_cc.rs)" >}}
```rust
use std::env;

use libafl_cc::{ClangWrapper, CompilerWrapper, Configuration, ToolWrapper};

pub fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let mut dir = env::current_exe().unwrap();
        let wrapper_name = dir.file_name().unwrap().to_str().unwrap();

        let is_cpp = match wrapper_name[wrapper_name.len()-2..].to_lowercase().as_str() {
            "cc" => false,
            "++" | "pp" | "xx" => true,
            _ => panic!("Could not figure out if c or c++ wrapper was called. Expected {dir:?} to end with c or cxx"),
        };

        dir.pop();

        let mut cc = ClangWrapper::new();
        if let Some(code) = cc
            .cpp(is_cpp)
            .parse_args(&args)
            .expect("Failed to parse the command line")
            .link_staticlib(&dir, "appsec_guide")
            .add_args(&Configuration::GenerateCoverageMap.to_flags().unwrap())
            .add_args(&Configuration::AddressSanitizer.to_flags().unwrap())
            .run()
            .expect("Failed to run the wrapped compiler")
        {
            std::process::exit(code);
        }
    } else {
        panic!("LibAFL CC: No Arguments given");
    }
}
```
{{< /customFigure >}}

The wrapper binary name determines whether the SUT is written in C or C++. Therefore, we added another binary in `src/bin/libafl_ccx.rs` to the project.


{{< customFigure "src/bin/libafl_cxx.rs: C++ compiler wrapper binary for LibAFL. [Full source code](https://github.com/trailofbits/testing-handbook/blob/main/materials/fuzzing/libafl/appsec_guide/src/bin/libafl_cxx.rs)" >}}
```rust
pub mod libafl_cc;

fn main() {
    libafl_cc::main();
}
```
{{< /customFigure >}}


We can now compile both wrappers by invoking:

```shell
cargo build --release
```

After that, we can compile the final fuzzer binary:

```shell
target/release/libafl_cxx -DNO_MAIN -g -O2 main.cc harness.cc -o fuzz
```

This creates several binaries, each with a different suffix. Because we need coverage instrumentation for our fuzzer, we need to use the `fuzz` binary. You can create more binaries with different instrumentations by adding more configurations using `add_configuration`. Note that the LibAFL fuzzer needs to be compatible with the instrumentations. For instance, adding the cmplog instrumentation in the wrapper script will not make the LibAFL fuzzer aware of the new instrumentation. You will need to adjust the observers and feedback in the fuzzer setup.

### Usage

To fuzz on a single core with an initial corpus stored in the `corpus/` directory, execute the following command:

```shell
./fuzz --cores 0 --input corpus
```

The fuzzer supports a few more options like `--timeout`, which finds inputs that exceed a certain execution time, and `--output`, which sets the directory where test cases are stored that either crash or cause a timeout.

The default output will look identical to the output observed in the section [LibAFL as libFuzzer drop-in replacement](#libafl-as-libfuzzer-drop-in-replacement). Additionally, the fuzzer we created in this section logs statistics to a hard-coded file called `fuzzer_stats.toml`.

The fuzzer will quickly find the bug from `main.cc`; however, by default, the fuzzer will not exit after finding a bug. Instead, it will continue fuzzing, and the `objectives` counter, which you can see in the terminal, will increase.

The following sections show additional APIs that demonstrate how extensible LibAFL is.

### Extending the fuzzer: Deduplicate crashes by hashing backtraces

The fuzzer we introduced above will store test cases in the output directory that crash because of the same bug. For instance, suppose that a test case causes a buffer overflow if the first four bytes contain an integer larger than the test case size. A mutation in the other bytes is a different test case, but they will likely trigger the same memory corruption. The output directory will quickly be filled with test cases that all reach the same memory corruption. To avoid this, we can use a LibAFL feature that analyzes the crash backtrace, and will store the test case only if the backtrace is novel.

This LibAFL feature requires two components:

* An observer that will look at backtraces when a crash occurs, and
* A feedback that is evaluated when a crash happens. The feedback checks if the crash backtrace is novel. If the crash has not been observed before, the feedback returns true.

First, we create the backtrace observer. Our example fuzzer needs to set the harness type to `InProcess` because each of our fuzzer clients uses the [`InProcessExecutor`](https://docs.rs/libafl/0.13.1/libafl/executors/inprocess/type.InProcessExecutor.html). Change this if you are using a fork server.


{{< customFigure "Creation of a backtrace observer that is not yet used anywhere. [Full source code](https://github.com/trailofbits/testing-handbook/blob/main/materials/fuzzing/libafl/appsec_guide_deduplicate/src/lib.rs)" >}}
```rust
let backtrace_observer = libafl::prelude::BacktraceObserver::owned("BacktraceObserver", libafl::observers::HarnessType::InProcess);
```
{{< /customFigure >}}

Next, we add the observer to the observer tuple in the executor declaration. If we do not add it here, then the observer will not be executed.


{{< customFigure "Updated declaration of the executor. [Full source code](https://github.com/trailofbits/testing-handbook/blob/main/materials/fuzzing/libafl/appsec_guide_deduplicate/src/lib.rs)" >}}
```rust
let mut executor = InProcessExecutor::with_timeout(
    &mut harness,
    tuple_list!(edges_observer, time_observer, backtrace_observer),
    &mut fuzzer,
    &mut state,
    &mut restarting_mgr,
    opt.timeout,
)?;
```
{{< /customFigure >}}

Finally, we update the objective definition with a `NewHashFeedback`. We use the `feedback_and` macro, so an objective is added only if a new backtrace is discovered. The feedback fetches the hash of the latest backtrace and stores it in a set. The feedback returns true only if the hash has not yet been observed.


{{< customFigure "Updated objective declaration. [Full source code](https://github.com/trailofbits/testing-handbook/blob/main/materials/fuzzing/libafl/appsec_guide_deduplicate/src/lib.rs)" >}}
```rust
let mut objective = feedback_and!(feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new()), libafl::feedbacks::new_hash_feedback::NewHashFeedback::new(&backtrace_observer));
```
{{< /customFigure >}}

{{< hint info >}}
PRO-TIP: We recommend running the fuzzer at least once without the deduplication after fixing the found crashes or if no crashes are found. Because LibAFL did not yet have a stable release, there might be bugs in the deduplication, leading to missed crashes. This feature is still helpful when you are fuzzing a target for the first time and have easy-to-reach crashes. After fixing the first batch of crashes rerun the fuzzer though without deduplication.
{{< /hint >}}

### Extending the fuzzer: Dictionary fuzzing

To fuzz with information from a dictionary, we first add a command-line option to the example fuzzer. We are using the [clap](https://github.com/clap-rs/clap) library to parse arguments. Here we add a tokens argument that uses the short flag `-x,` just as we did with AFL++. LibAFL uses the term ”set of tokens” to refer to a dictionary. The [dictionary format from AFL++](https://github.com/AFLplusplus/AFLplusplus/blob/stable/dictionaries/README.md) is compatible with the token files we are loading here.



{{< customFigure "New fuzzer argument that parses a dictionary file. [Full source code](https://github.com/trailofbits/testing-handbook/blob/main/materials/fuzzing/libafl/appsec_guide_tokens/src/lib.rs)" >}}
```rust
/// The commandline args this fuzzer accepts
#[derive(Debug, Parser)]
#[command(
    name = "appsec_guide",
    about = "A libfuzzer-like fuzzer with llmp-multithreading support and a launcher"
)]
struct Opt {
    ...

    #[arg(
    short = 'x',
    long,
    help = "Path to a tokens file",
    name = "TOKENS"
    )]
    tokenfile: Option<PathBuf>,
}
```
{{< /customFigure >}}

Next, we will use the path to the token file to load tokens. First, we create a `Tokens` struct and then fill it from the token file. After that, the tokens are added to the fuzzer state.


{{< customFigure "Read tokens from the file and add them to the fuzzer state." >}}
```rust
let mut state = state.unwrap_or_else(|| {
    ...
});

let mut tokens = Tokens::new();
if let Some(tokenfile) = &opt.tokenfile {
    tokens.add_from_file(tokenfile)?;
}

println!("Using tokens: {:?}", &tokens);

if !tokens.is_empty() {
    state.add_metadata(tokens);
}
```
{{< /customFigure >}}

Now that the fuzzer has access to the tokens, we need to add a mutation to the mutator that actually uses the metadata from the state. We extend the list of havoc mutations with token mutations.


{{< customFigure "Updated mutator that uses havoc and token mutations. [Full source code](https://github.com/trailofbits/testing-handbook/blob/main/materials/fuzzing/libafl/appsec_guide_tokens/src/lib.rs)" >}}
```rust
let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
```
{{< /customFigure >}}

We are now done with the basic setup of a fuzzer. If we have a very purpose-built fuzzer, then we may choose not to allow configuring the tokens through the command-line interface but instead hard-code them. For the PNG file format, for example, we could create the following tokens:


{{< customFigure "Hard-coded tokens for the PNG file format" >}}
```rust
state.add_metadata(Tokens::from([
    vec![137, 80, 78, 71, 13, 10, 26, 10], // PNG header
    "IHDR".as_bytes().to_vec(),
    "IDAT".as_bytes().to_vec(),
    "PLTE".as_bytes().to_vec(),
    "IEND".as_bytes().to_vec(),
]));
```
{{< /customFigure >}}

#### Auto token fuzzing

AFL++ originally introduced the [AUTODICTIONARY](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.lto.md#autodictionary-feature) feature, which uses a Clang compilation pass to extract magic values and checksums from the program. The fuzzer can then use these values to improve fuzzing coverage.

First, we want to update the `check_buf` function in the `main.cc` file to include a call to the `memcmp` function that the auto tokens feature can use to extract a value.


{{< customFigure "SUT with a call to memcmp. The fuzzer is comparing the input against the string “buf.” [Full source code](https://github.com/trailofbits/testing-handbook/blob/main/materials/fuzzing/libafl/appsec_guide_tokens/src/lib.rs)" >}}
```rust
void check_buf(char *buf, size_t buf_len) {
    if (buf_len >= 4) {
        if (memcmp(buf, "buf", 4) == 0) {
            abort();
        }
    }

    if(buf_len > 0 && buf[0] == 'a') {
        if(buf_len > 1 && buf[1] == 'b') {
            if(buf_len > 2 && buf[2] == 'c') {
                abort();
            }
        }
    }
}
```
{{< /customFigure >}}

The pass can be enabled in the `libafl_cc.rs` file by including the auto tokens pass.


{{< customFigure "Enabling the auto tokens compilation pass. [Full source code](https://github.com/trailofbits/testing-handbook/blob/main/materials/fuzzing/libafl/appsec_guide_tokens/src/lib.rs)" >}}
```rust
let mut cc = ClangWrapper::new();
if let Some(code) = cc
    .cpp(is_cpp)
    // silence the compiler wrapper output, needed for some configure scripts.
    .silence(true)
    .parse_args(&args)
    .expect("Failed to parse the command line")
    .link_staticlib(&dir, "appsec_guide")
    .add_args(&Configuration::GenerateCoverageMap.to_flags().unwrap())
    .add_args(&Configuration::AddressSanitizer.to_flags().unwrap())
    .add_pass(LLVMPasses::AutoTokens)
    .run()
    .expect("Failed to run the wrapped compiler")
{
    std::process::exit(code);
}
```
{{< /customFigure >}}

To verify that the Clang pass succeeded, you can use `gdb` to check whether the section has been populated.

```shell
echo "p (uint8_t *)__token_start" | gdb fuzz
```

If the global variable is null, then the pass has not been executed.

When we compile our SUT and harness with `libafl_cc`, a new section will be added to the fuzzer. We can read the compiled-in tokens during runtime and add them to the `Tokens` struct using the following code.


{{< customFigure "Inclusion of compiled-in autotokens. [Full source code](https://github.com/trailofbits/testing-handbook/blob/main/materials/fuzzing/libafl/appsec_guide_tokens/src/lib.rs)" >}}
```rust
tokens += libafl_targets::autotokens()?;
```
{{< /customFigure >}}

### Extending the fuzzer: Debugging

Sometimes you need to debug your LibAFL fuzzer. Its multiprocessing nature can make it difficult to attach with a debugger like GDB. A simple trick is to make the fuzzer run in a single process; instead of building a Launcher and then starting it, we can run the `run_client` closure directly. Simply comment on the launcher code and directly invoke the closure.


{{< customFigure "Adjusting the fuzzer to run in a single process." >}}
```rust
run_client(None, libafl::prelude::SimpleEventManager::new(monitor), 0).unwrap();

// match Launcher::builder()
//     .shmem_provider(shmem_provider)
//     .configuration(EventConfig::from_name("default"))
//     .monitor(monitor)
//     .run_client(&mut run_client)
//     .cores(&cores)
//     .broker_port(broker_port)
//     .remote_broker_addr(opt.remote_broker_addr)
//     .stdout_file(Some("/dev/null"))
//     .build()
//     .launch()
// {
//     Ok(()) => (),
//     Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
//     Err(err) => panic!("Failed to run launcher: {err:?}"),
// }
```
{{< /customFigure >}}

After that, you may run the fuzzer in GDB:

```shell
gdb --args ./fuzz --cores 0 --input corpus
```



## Real-world examples

### libpng

If you are fuzzing C projects that produce static libraries, you can follow this recipe:

1. Read the `INSTALL` file in the project’s codebase (or other appropriate documentation) and find out how to create a static library.
2. Set the compiler to your LibAFL-based fuzzer wrapper, and pass required flags to the compiler during compilation.
3. Build the static library by using the LibAFL compiler wrapper. The build step will create an instrumented static library, which we will refer to as `$static_library`.
4. Find the compiled static library from step 3 and call: `target/release/libafl-cxx $static_library harness.cc -o fuzz`.
5. You can start fuzzing by calling `./fuzz --input seeds/ --cores 0-8`.

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

Now, set up a variable that holds the path to the Cargo project:

```shell
export FUZZER_CARGO_DIR="/some/path"
```

Next, we configure and compile libpng as a static library without linking libFuzzer.

```shell
export CC=$FUZZER_CARGO_DIR/target/release/libafl_cc
export CXX=$FUZZER_CARGO_DIR/target/release/libafl_cxx
./configure --enable-shared=no # Configure to compile a static library
make # Run compilation
```

By default, the configuration script sets the optimization level to `-O2`, which is what we recommend in the [Compile a fuzz test](#compile-a-fuzz-test-libfuzzer) section.

Next, we download a harness from GitHub. Usually, you would have to write a harness yourself. However, for this example, an existing one suffices.

```shell
curl -O https://raw.githubusercontent.com/glennrp/libpng/f8e5fa92b0e37ab597616f554bee254157998227/contrib/oss-fuzz/libpng_read_fuzzer.cc
```

Finally, we link together the instrumented libpng, the harness, and the libFuzzer runtime.

```shell
$CXX libpng_read_fuzzer.cc .libs/libpng16.a -lz -o fuzz
```

Before we can launch the campaign, we need to prepare the seeds because AFL++ cannot start from an empty set of seeds. We do this by downloading a small example PNG file.

```shell
mkdir seeds/
curl -o seeds/input.png https://raw.githubusercontent.com/glennrp/libpng/acfd50ae0ba3198ad734e5d4dec2b05341e50924/contrib/pngsuite/iftp1n3p08.png
```

If you added the `-x` option to use a token file as explained in the previous section, then we can also download a [dictionary]({{% relref 02-dictionary %}}) for the PNG format to better guide the fuzzer. A dictionary provides the fuzzer with some initial clues about the file format, such as which magic bytes PNG uses.

```shell
curl -O https://raw.githubusercontent.com/glennrp/libpng/2fff013a6935967960a5ae626fc21432807933dd/contrib/oss-fuzz/png.dict
```

The fuzzing campaign can be launched by running:

```shell
./fuzz --input seeds/ --cores 0 -x png.dict
```

### CMake-based project

Let’s assume we are using CMake to build the program mentioned in the [introduction]({{% relref "fuzzing#introduction-to-fuzzers" %}}). We add a CMake target that builds the `main.cc` and `harness.cc` and links the target together with AFL++. Note that we are excluding the main function through the `NO_MAIN` flag; otherwise, the program would have two main functions.


{{< customFigure "CMake example" >}}
```cmake
project(BuggyProgram)
cmake_minimum_required(VERSION 3.0)

add_executable(buggy_program main.cc)

add_executable(fuzz main.cc harness.cc)
target_compile_definitions(fuzz PRIVATE NO_MAIN=1 )
target_compile_options(fuzz PRIVATE -g -O2)
```
{{< /customFigure >}}

The non-instrumented binary can be built with the following commands:

```shell
cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ .
cmake --build . --target buggy_program
```

Next, set up a variable that holds the path to the Cargo project:

```shell
export FUZZER_CARGO_DIR="/some/path"
```

From there, configure and compile libpng as a static library without linking libFuzzer.

The fuzzer can be built by choosing the fuzz target and changing the compiler:

```shell
cmake -DCMAKE_C_COMPILER=$FUZZER_CARGO_DIR/target/release/libafl_cc  -DCMAKE_CXX_COMPILER=$FUZZER_CARGO_DIR/target/release/libafl_cxx .
cmake --build . --target fuzz
```

The fuzzing campaign can be launched by running:

```shell
./fuzz --input seeds/ --cores 0
```

## Additional resources

* Official [handbook on LibAFL](https://aflplus.plus/libafl-book/)
* [Explanation of how to use LibAFL for a Rust project](https://github.com/AFLplusplus/LibAFL/tree/main/libafl_libfuzzer#usage)
  - An example [project that uses cargo-fuzz with the LibAFL shim](https://github.com/AFLplusplus/LibAFL/tree/main/fuzzers/fuzz_anything/cargo_fuzz)
