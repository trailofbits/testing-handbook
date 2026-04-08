---
title: "Linux usermode"
slug: lang-c-cpp-linux-usermode
weight: 12
---

# Linux usermode

This list covers common checks for and footguns of C/C++ standard libraries when used in Unix environments.

{{< checklist >}}

- [ ] Run [`checksec`](https://github.com/etke/checksec.rs) to learn about the executable's exploit mitigations.
  - Check for uses of NX, PIE, stack cookies, RELRO, `FORTIFY_SOURCE`, stack clash protector, SafeStack, ShadowCallStack, and other mitigations.
  - Check that production releases do not contain debug information.
- [ ] Check for uses of [non-thread-safe functions](https://www.gnu.org/software/libc/manual/html_node/POSIX-Safety-Concepts.html) in multi-threaded programs.
  - Some of these functions—such as [`gethostbyname`](https://man7.org/linux/man-pages/man3/gethostbyname.3.html#:~:text=pointers%20to%20static%20data%2C%20which%20may%20be%20overwritten%20by%20later%20calls.), [`inet_ntoa`](https://linux.die.net/man/3/inet_ntoa), [`strtok`](https://man7.org/linux/man-pages/man3/strtok.3.html), and [`localtime`](https://man7.org/linux/man-pages/man3/localtime.3.html)—may return pointers to static data. These pointers must be treated with care even in single-threaded programs, as they all may point to the same data.
- [ ] Check for uses of non-reentrant functions in signal handlers. See [lcamtuf's article](https://lcamtuf.coredump.cx/signals.txt).
  - [ ] The `errno` should not be modified in signal handlers (or must be saved and restored).
- [ ] Check that comparisons do not read data out of bounds.
  - `std::equal`, when called with three iterators to collections of unequal lengths, reads out of bounds.
  - `memcmp` may read out of bounds if the size argument is not computed correctly.
  - `strncmp` with strings of different length and invalid size may read out of bounds. See [`cstrnfinder`](https://github.com/disconnect3d/cstrnfinder) for string comparison bugs found in the wild.
- [ ] Check that environment variables are treated with care.
  - `getenv` and `setenv` [are not thread-safe](https://www.geldata.com/blog/c-stdlib-isn-t-threadsafe-and-even-safe-rust-didn-t-save-us#the-real-culprit-setenv-and-getenv) (though this was [recently improved in glibc](https://github.com/bminor/glibc/commit/7a61e7f557a97ab597d6fca5e2d1f13f65685c61)).
  - Letting users control environment variables is usually unsafe (consider [bash exported functions](https://archive.zhimingwang.org/blog/2015-11-25-bash-function-exporting-fiasco.html) and [`LIBC_FATAL_STDERR_`](https://github.com/j00ru/ctf-tasks/tree/master/CONFidence%20CTF%202015/Main%20event/Night%20Sky), for example).
  - If a high-privilege process creates a lower-privilege one, the new process can read its parent environment variables via the `procfs` filesystem.
    - `setenv(SOME_SENSITIVE_ENV, "overwrite", 1)` leaves the old environment value on the stack (readable via `/proc/$pid/environ`). Note that this may also be a DoS vector.
    - [`PR_SET_MM_ENV_START`](https://man7.org/linux/man-pages/man2/PR_SET_MM.2const.html)/`PR_SET_MM_ENV_END` `prctl` operations can be used to hide the environment. Overwriting of the parent process's stack memory at relevant addresses can also be used to hide the environment.
  - General-purpose libraries should use [`secure_getenv`](https://www.man7.org/linux/man-pages/man3/getenv.3.html) instead of `getenv` when possible
- [ ] Check that `open` and other related filesystem functions are treated with care.
  - Calls to `access` (to check for file existence) followed by calls to `open` are vulnerable to race conditions.
  - Calls to `rename` with attacker control over any part of the `destination` argument are [vulnerable to race conditions](https://gergelykalman.com/slides/the_forgotten_art_of_filesystem_magic.pdf).
  - Calls to `open` with the `O_NOFOLLOW` flag resolve directory symlinks; usually `RESOLVE_NO_SYMLINKS` or `O_NOFOLLOW_ANY` should be used instead.
  - Calls to `open` without the `O_CLOEXEC` flag leak file descriptors to child processes.
- [ ] Check that privilege dropping (through use of `seteuid`, `setgid`, etc., as well as implicit privilege dropping like during `execve` calls) is implemented with care.
  - Return values of privilege dropping functions must be checked.
    - Some function call combinations may fail to drop privileges without returning any errors. For example, `seteuid(X)` followed by `setuid(X)` may succeed without error but [fail to drop privileges permanently](https://www.usenix.org/legacy/events/sec02/full_papers/chen/chen.pdf).
    - [Group privileges should be dropped before user privileges](https://www.oreilly.com/library/view/secure-programming-cookbook/0596003943/ch01s03.html#:~:text=As%20discussed%20above%2C%20always%20drop%20group%20privileges%20before%20dropping%20user%20privileges%3B%20otherwise%2C%20group%20privileges%20may%20not%20be%20able%20to%20be%20fully%20dropped.).
    - Ideally, the new privileges [are explicitly checked after the dropping](https://people.eecs.berkeley.edu/~daw/papers/setuid-login08b.pdf). For example, `setuid(X)` should be followed by `if (getuid() == X)`.
    - Supplementary groups must be cleared with [`setgroups`](https://linux.die.net/man/2/setgroups) call when needed.
  - Running multiple threads with the same address-space but with different privilege levels is risky. See [`vfork`'s caveats](https://www.man7.org/linux/man-pages/man2/vfork.2.html#CAVEATS).
  - Permissions set through [`ioperm`](https://linux.die.net/man/2/ioperm), [record locks](https://linux.die.net/man/2/fcntl64), [interval timers](https://linux.die.net/man/2/setitimer), and [resource usage](https://linux.die.net/man/2/getrusage) information are preserved across calls to `execve` (but not `fork`).
  - File descriptors (regular, [locks](https://linux.die.net/man/2/flock), [timers](https://linux.die.net/man/2/timerfd_settime), etc.), [affinity masks](https://linux.die.net/man/2/sched_getaffinity), [scheduling policies](https://linux.die.net/man/2/sched_getscheduler), [signal masks](https://linux.die.net/man/2/rt_sigprocmask), [session IDs](https://linux.die.net/man/2/setsid), [process group IDs](https://linux.die.net/man/2/getpgid), [supplementary groups](https://linux.die.net/man/2/setgroups), [resource limits](https://linux.die.net/man/2/setrlimit), and `NO_NEW_PRIVS` prctl settings are preserved across calls to `fork` and `execve`.
  - Inheritance of [capabilities](https://linux.die.net/man/7/capabilities) is complex. Read the manual for every capability that your parent program has and that a child should not inherit.
- [ ] Look for uses of the many unsafe stdlib functions that should not be used.
  - Such functions include `sprintf`, `vsprintf`, `strcpy`, `stpcpy`, `strcat`, `gets`, `scanf` with `%s` (no bounds checking), `tmpnam`, `tempnam`, `mktemp` (race conditions), `alloca`, and `putenv` (overcomplicated memory management).
- [ ] Check that all errors returned as return values are handled correctly.
  - Look for return value checks on calls to `(v)s(n)printf`,  `write`, `read`, and other functions that may return negative values. Mishandling negative returns is quite a classic issue.
  - The `mmap` function returns `MAP_FAILED` on error, not `NULL`.
  - Functions like [`atoi`](https://man7.org/linux/man-pages/man3/atoi.3.html) do not inform about errors at all and likely should not be used.
- [ ] Look for proper handling of functions whose return values are insufficient to distinguish success from failure. For such functions, the `errno` must be cleared before a call (otherwise, the `errno` value may be a leftover from some previous function call).
  - Functions like `clock` and `times` return `-1` on error and for legitimate wrap-around of the clock tick.
  - Functions like `strtol`, `strtoull`, `pow`, and `log` return boundary values (like `LONG_MAX`) on both valid input and `ERANGE` overflow.
  - Functions like `getchar` and `fgetc` return `EOF` for errors and actual end-of-file states.
  - Functions like `dlsym` return `NULL` on error and for some legitimate non-error cases. The `dlerror` method must be consulted in addition to the return value.
- [ ] Examine uses of `snprintf` to ensure the return value is handled correctly.
  - Its return value is confusing and often misunderstood: it returns the number of characters *that would have been written* to the final string if enough space had been available, not how many bytes were actually written.
- [ ] Look for proper handling of functions that return success without completing the job.
  - Functions like `read` and `write` may not error out but still not finish the job. For example, `read` may have not read the requested amount of bytes and likely should be repeated.
- [ ] Look for proper error handling on calls to `write`, `read`, and other functions that do not handle `EINTR` errors.
  - Calls to most stdlib functions should usually be repeated after this error. See [this resource](https://android.googlesource.com/platform/bionic/+/master/docs/EINTR.md) on EINTR errors.
  - The [`close` function is an exception](https://lwn.net/Articles/576478/); it must not be called again after the `EINTR` error.
- [ ] Look for overlapping buffers as inputs to `snprintf`, `vsprintf`, `memcpy`, and other functions, as they may be problematic.
  - Passing the same buffer as input and output often results in undefined behavior.
  - When `source` plus `offset` memory overlaps with `destination`, the function call may result in undefined behavior.
- [ ] Examine uses of `strlen` combined with `strcpy`, as this combination is likely to miscount the null byte.
  - `strlen` does not include the `NULL` terminator in the returned length, but `strcpy` copies the `NULL`. See [this X post](https://twitter.com/h0mbre_/status/1396529223372840963/photo/1) for details.
- [ ] Examine inputs to `scanf("%d", &x)` for cases that could lead to uninitialized data leaks.
  - Passing invalid characters like `-` and `+` as input prevents `scanf` from changing the `x` variable, potentially leading to such leaks.
- [ ] Examine uses of `strncat`, as it is commonly misused.
  - The `size` argument is for the size of the `source` string, not the `destination` buffer.
- [ ] Examine uses of `strncpy`, as it may not always null-terminate the destination string.
- [ ] Look for uses of glibc's [`qsort`](https://man7.org/linux/man-pages/man3/qsort.3.html), `std::sort` and [`std::stable_sort`](https://en.cppreference.com/w/cpp/algorithm/stable_sort.html) functions called with a [non-transitive sort function](https://www.qualys.com/2024/01/30/qsort.txt), as they are exploitable.
- [ ] Look for uses of `memcpy` and `memmove` (and possibly other functions) with negative `size` arguments, as these cases are likely to be [exploitable](https://github.com/n132/RetroverFlow).
  - Negative integer overflows to the large `size_t` look to be non-exploitable, as large writes should trigger a crash before anything useful can be done. However, optimizations may make the overflow exploitable, [depending on the libc version and CPU features](https://x.com/disconnect3d_pl/status/1909918427084452076).
- [ ] Look for calls to spinlock functions (like [`pthread_spin_trylock`](https://man7.org/linux/man-pages/man3/pthread_spin_lock.3.html)) on a non-initialized lock.
- [ ] Look for uses of the `inet_aton` function to check if a string is a valid IP address. It should not be used in this way, as the function [is not strict](https://disconnect3d.pl/2021/02/16/terrible-inet-aton/).
  - When linked with glibc, it returns success if the passed-in host address *starts with* a valid IP address, not just if it is a valid IP address. For example, this call returns success: `inet_aton("1.1.1.1 whatever")`.
- [ ] Check for vulnerable uses of `connect(AF_UNSPEC)`, as it can be used to disconnect an already connected TCP socket.
  - The socket can be reconnected to a new address. This trick allowed for [nsjail escapes in the past](https://github.com/google/nsjail/commit/273ce6bc846b7325c7f0915067c54bf8cf6f5654).
- [ ] Check for cases in which sockets may be only half-closed (via the `shutdown` function).
  - This could be useful for exploitation when the remote endpoint has a vulnerability only after the connection was closed but data still needs to be read (or written) via the socket.
- [ ] Look for dynamic-size structs implemented with [zero-length and one-element arrays, as they are error-prone](https://github.com/torvalds/linux/blob/master/Documentation/process/deprecated.rst#zero-length-and-one-element-arrays).
- [ ] Examine any custom `printf`\-like functions to ensure that the [`format` attribute](https://clang.llvm.org/docs/AttributeReference.html#format) is used to prevent variadic type misuse.
- [ ] Examine uses of `va_start` to ensure it is always used with `va_end`. See this [StackOverflow discussion](https://stackoverflow.com/questions/587128/what-exactly-is-va-end-for-is-it-always-necessary-to-call-it) for details.
- [ ] Check that [zero is not used in place of `NULL`](https://man7.org/linux/man-pages/man3/NULL.3const.html).
{{< /checklist >}}
