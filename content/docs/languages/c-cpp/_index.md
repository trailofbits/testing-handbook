---
title: "C/C++ Security Checklist"
slug: lang-c-cpp
weight: 1
bookCollapseSection: true
---

# Security Checklist for C/C++ Programs

C and C++ are two of the most-used languages for applications and system programming. This security checklist, written for security auditors and secure development practitioners, provides a wide range of security issues to look for when reviewing C and C++ code. It covers both language-specific bug classes and environment-specific security issues spanning the Linux and Windows operating systems, including usermode applications and kernelmode drivers. While no checklist can be exhaustive, we hope that this document serves as a strong starting point for the most common and impactful security issues that may be found in C and C++ code.

## Bug classes

Below is a list of common vulnerability types for C/C++ programs. This list does not include comprehensive details; rather, it is intended to be broad and high level. Use it as a starting point during security reviews of C/C++ programs.

- [ ] Buffer overflow and underflow, spatial safety
  - [ ] Off-by-one mistakes
  - [ ] Invalid computation of object sizes
  - [ ] Misunderstanding of data-moving functions' semantics
  - [ ] Data comparison using out-of-bounds lengths
  - [ ] [Copying of raw memory instead of the object](https://ctftime.org/writeup/16283)
  - [ ] [Out-of-bounds iterators](https://github.com/MicrosoftDocs/cpp-docs/blob/main/docs/standard-library/checked-iterators.md)

- [ ] Use after free, temporal safety
  - [ ] Use after free
    - Example: Two `shared_ptr`s point to the same object, and one of them decrements its reference count (refcount) to 0 and frees the object. See [this blog post](https://blog.scrt.ch/2017/01/27/exploiting-a-misused-c-shared-pointer-on-windows-10/) for reference.
  - [ ] Use after scope, dangling pointers
    - Example: Heap structures owning pointers to stack variables
  - [ ] Use after return
    - Example: With `return string("").c_str()`, the string's internal buffer is destroyed on return.
  - [ ] Use after close
    - Example: A file's descriptor is saved in process memory, the file is closed, and then another file is assigned to the same descriptor. See [this CTF challenge](https://github.com/j00ru/ctf-tasks/tree/master/CONFidence%20CTF%202017/Main%20event/Filesystem).
  - [ ] Use after move
  - [ ] Double free
  - [ ] Misuse of smart pointers. See [this example CTF writeup](https://blog.scrt.ch/2017/01/27/exploiting-a-misused-c-shared-pointer-on-windows-10/).
  - [ ] Lambda capture issues
  - [ ] Arbitrary pointer free
    - Example: An attacker can call `free` on a pointer to memory that was not dynamically allocated or on data that is not a pointer.
  - [ ] Incorrect refcounts
    - Example: A refcount is incremented when it should not be, or an object is not freed when its refcount drops to zero.
  - [ ] Partial free
    - Example: A struct's field is freed but the struct is not, or vice versa.
  - [ ] Misuse of memory-allocating library functions
    - Example: OpenSSL's `BN_CTX_start` is called without a corresponding call to `BN_CTX_end`. See [this blog post](https://github.blog/2021-02-25-the-little-bug-that-couldnt-securing-openssl/) for reference.

- [ ] Integer overflow, numeric errors
  - [ ] Arithmetic overflows
    - Results of computations do not fit in intermediate or final types.
  - [ ] Widthness overflows
    - Data is assigned to a too-small type.
  - [ ] Signedness bugs
    - Data is transformed in unexpected ways when its type's sign changes.
  - [ ] Implicit conversions
    - The type of a variable changes unexpectedly.
  - [ ] Negative assignment overflow
    - `abs(-INT_MIN) == -INT_MIN`
    - `int a = -b` (if `b = INT_MIN`, then `a = b`)
  - [ ] Integer cut
    - Example: The code reads `rax`, compares only `eax`, and then uses `rax`.
  - [ ] Rounding errors
  - [ ] Float imprecision
    - Example: Direct comparison of floats without an epsilon

- [ ] Type confusion, type safety issues
  - [ ] Type confusion when casting
  - [ ] Type confusion when deserializing
  - [ ] Type confusion when dereferencing pointers (pointer to pointer instead of pointer)
  - [ ] Void pointers
  - [ ] Type safety issues related to unions
  - [ ] [Object slicing](https://pvs-studio.com/en/docs/warnings/v1054/)

- [ ] Variadic function misuse
  - [ ] Format string bugs
    - User input is used as the format string.
  - [ ] Type mismatch bugs
    - A format string specifier does not match the type of the provided argument.

- [ ] String issues
  - [ ] Lack of null termination
  - [ ] Issues related to [locale-dependent](https://cppreference.com/w/cpp/locale.html) string operations
    - When the execution environment may impact the logic of the code in unexpected ways
  - [ ] Problems related to encoding and normalization (UTF-8, UTF-16, Unicode, etc.)
  - [ ] Byte size not equal to character size
    - Example: When [multibyte or wild](https://learn.microsoft.com/en-us/cpp/c-language/multibyte-and-wide-characters?view=msvc-170) characters are used

- [ ] Use of uninitialized data

- [ ] Null pointer dereferences

- [ ] Unhandled errors
  - [ ] Return values not checked
  - [ ] Return values incorrectly compared
    - Example: When a function returns 1 on success and 0 or negative on failure, but the code includes an `if (retval != 0)` check
  - [ ] Exception handling issues

- [ ] Memory leaks
  - [ ] Uninitialized memory exposure
    - Example: Via padding in structures
  - [ ] Exposure of pointers

- [ ] Initialization order bugs
  - Example: [Static initialization order fiasco](https://en.cppreference.com/w/cpp/language/siof.html)

- [ ] Race conditions
  - [ ] Time-of-check to time-of-use (TOCTOU)
  - [ ] [double fetch](https://j00ru.vexillium.org/slides/2013/syscan.pdf)
  - [ ] Over- or under-locking
  - [ ] (Non-)thread-safe and signal-safe APIs

- [ ] Filesystem-related issues
  - [ ] Issues with softlinks/symlinks
  - [ ] Disk synchronization issues (fsyncing/flushing of data)
  - [ ] Mishandling of unquoted paths (which may contain whitespace characters)
  - [ ] Missing path separators (e.g., `C:\app\files` vs `C:\app\files\` versus `C:\app\files_sensitive`)
  - [ ] [Case sensitivity and normalization issues](https://eclecticlight.co/2021/05/08/explainer-unicode-normalization-and-apfs/)
  - [ ] Predictable temporary files

- [ ] Iterator invalidation (see Trail of Bits' [blog post](https://blog.trailofbits.com/2020/10/09/detecting-iterator-invalidation-with-codeql/) for reference)
  - [ ] Accidental deletion of a list item while iterating over it

- [ ] Usage of error-prone functions
  - See Intel's [SDL List of Banned Functions](https://github.com/intel/safestringlib/wiki/SDL-List-of-Banned-Functions)

- [ ] Denial of service
  - [ ] High resource usage
  - [ ] Leaks of resources, file descriptors, or memory
  - [ ] Passing containers (e.g., `vector`) via value instead of via reference
  - [ ] Dangling references (e.g., after `move` or in `lambda` captures)

- [ ] Undefined behavior
  - [ ] Invalid alignment
  - [ ] Strict aliasing violation
  - [ ] Signed integer overflow
  - [ ] Shift by negative integer
  - [ ] Shift by \>= the type's width
  - [ ] And so many others…

- [ ] Compiler-introduced bugs
  - [ ] Removal of security checks due to assumptions around undefined behavior
    - [Removal of null pointer checks](https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html#index-fdelete-null-pointer-checks) and [array bound checks](https://docs.google.com/presentation/d/1pAosPlKUw4uI5lfg7FVheTZAtI5mUy8iDeE4znprV34/edit?slide=id.g355abfaddab_0_5#slide=id.g355abfaddab_0_5) due to null pointer dereference being UB
    - Removal of integer overflow checks because signed integer overflow is UB
  - [ ] Removal of data zeroization function calls
  - [ ] Issues resulting from optimization of constant-time constructions
  - [ ] Removal of debug assertions in production builds

- [ ] Operator precedence issues

- [ ] Problems with time
  - [ ] Clocks may be non-monotonic.
  - [ ] Time may change backward (time zones, [daylight saving time](https://en.wikipedia.org/wiki/Daylight_saving_time), [leap seconds](https://cr.yp.to/proto/utctai.html)).

- [ ] Access control issues
  - [ ] Invalid dropping of privileges (see the USENIX Association's [paper](https://www.usenix.org/legacy/events/sec02/full_papers/chen/chen.pdf) for information on `setuid` bugs)
  - [ ] Untrusted data used in privileged context (e.g., usermode data used inside the kernel with these sensitive x86 instructions: [`out`](https://www.felixcloutier.com/x86/out), [`wrmsr`](https://www.felixcloutier.com/x86/wrmsr), [`rdmsr`](https://www.felixcloutier.com/x86/rdmsr), [`xsetbv`](https://www.felixcloutier.com/x86/xsetbv), and `mov` to the control register)

- [ ] Invalid regular expressions (regexes)
  - [ ] ReDoS attacks possible
  - [ ] Multi-line (newline) bypasses

- [ ] Lack of exploit mitigations
  - [ ] Compile-time mitigations
  - [ ] Runtime mitigations
  - [ ] [libc++ hardenings](https://libcxx.llvm.org/Hardening.html)
  - [ ] [Typos in exploit mitigation configurations](https://blog.trailofbits.com/2023/04/20/typos-that-omit-security-features-and-how-to-test-for-them/)

## Linux usermode

This list covers common checks for and footguns of C/C++ standard libraries when used in Unix environments.

- [ ] Run [`checksec`](https://github.com/etke/checksec.rs) to learn about the executable's exploit mitigations.
  - Check for uses of NX, PIE, stack cookies, RELRO, `FORTIFY_SOURCE`, stack clash protector, SafeStack, ShadowCallStack, and other mitigations.
  - Check that production releases do not contain debug information.

- [ ] Check for uses of [non-thread-safe functions](https://www.gnu.org/software/libc/manual/html_node/POSIX-Safety-Concepts.html) in multi-threaded programs.
  - Some of these functions—such as [`gethostbyname`](https://man7.org/linux/man-pages/man3/gethostbyname.3.html#:~:text=pointers%20to%20static%20data%2C%20which%20may%20be%20overwritten%20by%20later%20calls.), [`inet_ntoa`](https://linux.die.net/man/3/inet_ntoa), [`strtok`](https://man7.org/linux/man-pages/man3/strtok.3.html), and [`localtime`](https://man7.org/linux/man-pages/man3/localtime.3.html)—may return pointers to static data. These pointers must be treated with care even in single-threaded programs, as they all may point to the same data.

- [ ] Check for uses of non-reentrant functions in signal handlers. See [lcamtuf's article](http://lcamtuf.coredump.cx/signals.txt).
  - [ ] The `errno` should not be modified in signal handlers (or must be saved and restored).

- [ ] Check that comparisons do not read data out of bounds.
  - `std::equal`, when called with three iterators to collections of unequal lengths, reads out of bounds.
  - `mecmp` may read out of bounds if the size argument is not computed correctly.
  - `strncmp` with strings of different length and invalid size may read out of bounds. See [`cstrnfinder`](https://github.com/disconnect3d/cstrnfinder) for string comparison bugs found in the wild.

- [ ] Check that environment variables are treated with care.
  - `getenv` and `setenv` [are not thread-safe](https://www.geldata.com/blog/c-stdlib-isn-t-threadsafe-and-even-safe-rust-didn-t-save-us#the-real-culprit-setenv-and-getenv) (though this was [recently improved in glibc](https://github.com/bminor/glibc/commit/7a61e7f557a97ab597d6fca5e2d1f13f65685c61)).
  - Letting users control envvars is usually unsafe (consider [bash exported functions](https://archive.zhimingwang.org/blog/2015-11-25-bash-function-exporting-fiasco.html) and [`LIBC_FATAL_STDERR_`](https://github.com/j00ru/ctf-tasks/tree/master/CONFidence%20CTF%202015/Main%20event/Night%20Sky), for example).
  - If a high-privilege process creates a lower-privilege one, the new process can read its parent environment variables via the `procfs` filesystem.
    - `setenv(SOME_SENSITIVE_ENV, "overwrite", 1)` leaves the old environment value on the stack (readable via `/proc/$pid/environ`). Note that that this may also be a DoS vector.
    - [`PR_SET_MM_ENV_START`](https://man7.org/linux/man-pages/man2/PR_SET_MM.2const.html)/`PR_SET_MM_ENV_END` `prctl` operations can be used to hide the environment. Overwriting of the parent process's stack memory at relevant addresses can also be used to hide the environment.
  - General-purpose libraries should use [`secure_getenv`](https://www.man7.org/linux/man-pages/man3/getenv.3.html) instead of `getenv` when possible

- [ ] Check that `open` and other related filesystem functions are treated with care.
  - Calls to `access` (to check for file existence) followed by calls to `open` are vulnerable to race conditions.
  - Calls to `rename` with attacker control over any part of the `destination` argument are [vulnerable to race conditions](https://gergelykalman.com/slides/the_forgotten_art_of_filesystem_magic.pdf).
  - Calls to `open` with the `O_NOFOLLOW` flag resolve directory symlinks; usually `O_NOFOLLOW_ANY` should be used instead.
  - Calls to `open` without the `O_CLOEXEC` flag leak file descriptors to child processes.

- [ ] Check that privilege dropping (through use of `seteuid`, `setgid`, etc., as well as implicit privilege dropping like during `execve` calls) is implemented with care.
  - Return values of privilege dropping functions must be checked.
    - Some function call combinations may fail to drop privileges without returning any errors. For example, `seteuid(X)` followed by `setuid(X)` may succeed without error but [fail to drop privileges permanently](https://www.usenix.org/legacy/events/sec02/full_papers/chen/chen.pdf).
    - [Group privileges should be dropped before user privileges](https://www.oreilly.com/library/view/secure-programming-cookbook/0596003943/ch01s03.html#:~:text=As%20discussed%20above%2C%20always%20drop%20group%20privileges%20before%20dropping%20user%20privileges%3B%20otherwise%2C%20group%20privileges%20may%20not%20be%20able%20to%20be%20fully%20dropped.).
    - Ideally, the new privileges [are explicitly checked after the dropping](https://people.eecs.berkeley.edu/~daw/papers/setuid-login08b.pdf). For example, `setuid(X)` should be followed by `if (getuid() == X)`.
    - Supplementary groups must be cleared with [`setgroups`](https://linux.die.net/man/2/setgroups) call when needed.
  - Running multiple threads with the same address-space but with different privilege levels is risky. See [`vfork`'s caveats](https://www.man7.org/linux/man-pages/man2/vfork.2.html#CAVEATS).
  - Permissions set through [`ioperm`](https://linux.die.net/man/2/ioperm), [record locks](https://linux.die.net/man/2/fcntl64), [interval timers](https://linux.die.net/man/2/setitimer), and [resource usage](https://linux.die.net/man/2/getrusage) information are preserved across calls to `execve` (but not `fork`).
  - File descriptors (regular, [locks](https://linux.die.net/man/2/flock), [timers](https://linux.die.net/man/2/timerfd_settime), etc.), [affinity masks](https://linux.die.net/man/2/sched_getaffinity), [scheduling policies](https://linux.die.net/man/2/sched_getscheduler), [signal masks](https://linux.die.net/man/2/rt_sigprocmask), [session IDs](https://linux.die.net/man/2/setsid), [process group IDs](https://linux.die.net/man/2/getpgid), [supplementary groups](http://linux.die.net/man/2/setgroups), [resource limits](https://linux.die.net/man/2/setrlimit), and `NO_NEW_PRIVS` prctl settings are preserved across calls to `fork` and `execve`.
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
  - Functions like `dlsym` return `NULL` on error and for some non-errorness cases. The `dlerror` method must be consulted in addition to the return value.

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

## Linux kernel

This list includes basic checks for Linux kernel drivers and modules.

- [ ] Check that all uses of data coming from the userspace are validated.
  - Look for the [`__user` tag](https://elixir.bootlin.com/linux/v6.16/source/include/linux/compiler_types.h#L31) in the code. Not necessarily all userspace data is marked with the tag, but it is a good start.
  - Uses of [`copy_from_user(to, from, size)`](https://elixir.bootlin.com/linux/v6.16/source/include/linux/uaccess.h#L205) should be validated:
    - The length should be validated correctly.
    - There should be no uninitialized `to` addresses.
    - The low-level [`__copy_from_user`](https://elixir.bootlin.com/linux/v6.16/source/include/linux/uaccess.h#L102) function should be used with the [`access_ok`](https://elixir.bootlin.com/linux/v6.16/source/include/asm-generic/access_ok.h#L31) identifier.

- [ ] Check that uses of [`copy_to_user(to, from, size)`](https://elixir.bootlin.com/linux/v6.16/source/include/linux/uaccess.h#L217) are validated.
  - `from` memory should be initialized (including the struct's padding).

- [ ] Review uses of [`user_access_{begin,end}`](https://elixir.bootlin.com/linux/v6.16/source/include/linux/uaccess.h#L551-L552).
  - These calls make kernel code disable/enable [SMAP](https://en.wikipedia.org/wiki/Supervisor_Mode_Access_Prevention). Any code between these calls must be reviewed carefully.

- [ ] Review other userspace-to-kernel methods.
  - At least the following functions should be reviewed: `get_user`, `strncpy_from_user`, `copy_struct_from_user`, `access_process_vm`, and `get_user_pages`.
  - Review uses of explicitly unsafe functions such as `__put_user` and `unsafe_put_user` with extra care.

- [ ] Check for instances in which the kernel fetches or copies memory from userspace twice instead of once, which results in TOCTOU (or double fetch) issues.
  - This often happens when pre- or post-syscall hooks are involved.

- [ ] Review the codebase for pointer leaks.
  - For example, use of the `%p` format string may leak kernel addresses. The mitigation for this particular issue is to use [`kptr_restrict`](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#kptr-restrict). Developers should use the `%pK` or `%p`x format strings.

- [ ] Check that file descriptors passed to userspace (with [`fd_install`](https://elixir.bootlin.com/linux/v6.16/source/fs/file.c#L637), for example) are [not used by the kernel anymore](https://github.com/torvalds/linux/commit/f1ce3986baa62cffc3c5be156994de87524bab99).
  - Userspace can call `close` or `dup2` on the descriptor to make it point to a different file, and the kernel would then use a different file structure than the expected one, which may lead to issues like use after free.

- [ ] Check for uses of [`strlen_user`](https://elixir.bootlin.com/linux/v3.19.8/source/lib/strnlen_user.c#L126) and `strnlen_user` (which are used only in old kernels). These functions return the length *including* the nullbyte, which is different behavior from the userspace `strlen` function and may be confusing.

- [ ] Examine uses of [`strncpy_from_user`](https://elixir.bootlin.com/linux/v6.16/source/lib/strncpy_from_user.c#L113), as they may not null-terminate the destination string (same behavior as stdlib `strncpy`).

- [ ] Check that reference counting [is implemented correctly](https://blog.lexfo.fr/cve-2017-11176-linux-kernel-exploitation-part1.html) (`fget`/`fput`, `sock_hold`/`sock_put`, `get_pid_task/get_task_struct/put_task_struct`, `{get,put}_pid`, `d_find_alias/dget/dput`, etc.).
  - There are no double decrements (causing use-after-free conditions).
  - There are no missing increments (causing use-after-free conditions).
  - There are no double increments (causing dangling objects).
  - There are no missing decrements (causing dangling objects).
  - The correct type is used for custom refcounters ([`refcount_t` versus `atomic_t`](https://www.kernel.org/doc/html/v4.16/core-api/refcount-vs-atomic.html)).
  - Return values of refcount-taking functions like [`try_module_get`](https://www.kernel.org/doc/html/next/driver-api/basics.html#c.try_module_get) are checked.

- [ ] Check that mutex locking is implemented correctly (`mutex_lock`, `spin_lock`).

- [ ] Check that the [`__ro_after_init`](https://www.kernel.org/doc/html/latest/security/self-protection.html#:~:text=For%20variables%20that%20are%20initialized%20once%20at%20__init%20time%2C%20these%20can%20be%20marked%20with%20the%20__ro_after_init%20attribute.) attribute is used for init-once variables.

- [ ] Examine dynamic allocations to ensure they are correct.
  - [The right version of free is always used](https://github.com/torvalds/linux/blob/master/scripts/coccinelle/api/kfree_mismatch.cocci) (e.g., `kmalloc-kfree` versus `vmalloc-vfree`).
  - The return value is checked against `NULL`.
  - [Zeroing functions are used instead of allocation and `memset`](https://github.com/torvalds/linux/blob/master/scripts/coccinelle/api/alloc/zalloc-simple.cocci).
  - [Oops is not possible between a stack-based allocation (`vmalloc`) and corresponding free](https://blog.quarkslab.com/nvidia_gpu_kernel_vmalloc_exploit.html).

- [ ] Check that if a global initialization function (like [`genl_register_family`](https://www.infradead.org/~tgr/libnl/doc/api/group__genl__mngt.html#gac625c0fe5d060cb587efcbeaa44b3ff2) and [`init_module`](https://elixir.bootlin.com/linux/v6.16/source/include/linux/module.h#L76)) allocates memory, the corresponding deinitialization function frees the memory.

- [ ] For code that modifies protection of kernel memory mappings, check that any read-only pages, like syscall tables, stay read-only after the modification.

- [ ] Check that all interfaces (procfs entries, sysfs files, device files, ioctl and netlink operations, etc.) that allow administrative operations to be performed or sensitive data to be obtained (via pointers, configuration, etc.) require root user and relevant [capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html).
  - Low-privilege users can become root (users with UID 0\) in their own namespace (e.g., inside a Docker container). Missing capability checks could allow root-owned procfs files to be accessed or [kernel pointers to be leaked](https://blog.trailofbits.com/2024/03/08/out-of-the-kernel-into-the-tokens/#:~:text=of%20expected%20algorithms.-,KASLR%20bypass%20in%20privilege%2Dless%20containers,-Next%20is%20a).

- [ ] Ensure capability checks for the correct process(es) are performed.
  - For example, there should be capability checks not only of the calling process but also of the process that created a resource. See [CVE-2023-2002](https://marc.info/?l=oss-security&m=168164424404224) for more information.

- [ ] Check that custom filesystems (defined by the `file_system_type` struct) and files (defined by the `file_operations` struct) have the [`owner` field set to `THIS_MODULE`](https://www.kernel.org/doc/html/next/filesystems/vfs.html).

- [ ] Use kernel-specific static analysis.
  - The main tool is Coccinelle. Use it with rules from the [Linux repo](https://github.com/torvalds/linux/tree/master/scripts/coccinelle) and the [Coccinelle website](https://coccinelle.gitlabpages.inria.fr/website/impact_linux.html) (they must be downloaded manually).

## Windows usermode

- [ ] Run [binskim](https://github.com/microsoft/binskim) to check mitigation opt-in and other issues in the application binaries.
  - DEP (NX), ASLR (and HiASLR on x86\_64), Control Flow Guard (CFG), and SafeSEH (on x86\_32 only) should always be enabled, and executables should be signed.
  - Shadow stack (CET) and Spectre mitigations may be enabled for additional security.
  - Production releases do not contain PDB files and debugging information.
- [ ] Check that installation processes do not have race conditions when extracting files (e.g., being able to overwrite temp files during extraction, which are then copied to protected or privileged paths).
  - Can you exploit this to add a symlink to a critical system file and have the installer overwrite it, leading to a permanent DoS?
  - Can you [abuse MSI rollback behavior to turn a file deletion into privilege escalation](https://cloud.google.com/blog/topics/threat-intelligence/arbitrary-file-deletion-vulnerabilities/)? See also [this ZDI writeup](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks).
- [ ] Check for failed DLL loads at runtime.
  - Use [procmon](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) to watch the process as it starts, and look for attempted file accesses on DLLs that do not exist. It is pretty common to see failed attempts to load localization and similar DLLs because they do not exist on that platform, which can be exploited by planting a DLL with the same name in the working directory.
  - See a guide to configuring procmon for this purpose at the end of [this MSDN article](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-security).
  - See also this [Node.js-specific example](https://www.atredis.com/blog/2025/3/7/node-is-a-loader) and this [Electron-specific example](https://hexiosec.com/blog/dll-hijacking-and-proxying/) of failed DLL loads.
- [ ] Check for [`LoadLibrary`](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya) calls that might be vulnerable to DLL planting.
  - Are they loading from a safe path?
  - A full path to the binary should be specified to prevent DLL planting attacks.
    - Ensure that path generation uses trusted data. The current working directory may be controllable by an attacker. If the load path is pulled from registry or configuration files, do they have appropriate ACLs?
  - [`LoadLibraryEx`](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexa) can be used for improved security:
    - Load locations can be restricted with the search flags (e.g., `LOAD_LIBRARY_SEARCH_SYSTEM32` to only load from System32).
    - `LOAD_LIBRARY_REQUIRE_SIGNED_TARGET` can be specified to mandate that the target is signed (e.g., [Authenticode signed](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/authenticode)).
- [ ] Check for [`CreateProcess`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa) calls that might be vulnerable to executable planting due to unquoted paths.
  - If `lpApplicationName` is `NULL`, `lpCommandLine` is used as a whitespace-delimited command and arguments. If the executable path has a space in it and it is not quoted, then Windows will try to execute that path fragment first (e.g., `C:\Program Files\Application\test.exe` will attempt to run `C:\Program.exe` first). This can be mitigated by wrapping the complete path in quotes.
    - Note that this applies to spaces in subdirectories, too: if `C:\Users\user\AppData\Local\App\Some Dir\update.exe` is unquoted, then Windows will try to run `C:\Users\user\AppData\Local\App\Some.exe` first.
  - If the target is a `.cmd` or `.bat` file, it may be possible to plant a malicious `cmd.exe` in the same directory as the program on old systems. See [MS14-019](https://msrc.microsoft.com/blog/2014/04/ms14-019-fixing-a-binary-hijacking-via-cmd-or-bat-file/).
    - This vulnerability is only really relevant if there is an expectation that a user might run the application on an old WinXP or Server 2003 system that is not patched for it (e.g., industrial, medical, or lab equipment).
- [ ] If a high-privilege process creates a lower-privilege process or a process running as another user, check that the process disables handle inheritance.
  - On `CreateProcess(AsUser)`, the `bInheritHandles` parameter controls this.
  - Sensitive handles owned by the higher-privilege process could be transferred to the lower-privilege process.
- [ ] If a high-privilege process creates a lower-privilege process or a process running as another user, check that the process passes `DETACHED_PROCESS` or `CREATE_NEW_CONSOLE`.
  - If not, the lower-privilege process shares access to the high-privilege process console object, meaning that `stdin`, `stdout`, and `stderr` can be manipulated by both processes. This may be relevant for console applications or for programs that manipulate data through `stdin`/`stdout`.
- [ ] Check whether the [`CREATE_PRESERVE_CODE_AUTHZ_LEVEL`](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags) flag is passed to `CreateProcess`. Doing so [bypasses AppLocker and SRP](https://skanthak.hier-im-netz.de/appcert.html) on Windows Vista and unpatched Windows 7\.
- [ ] Investigate any `CreateProcess` calls made with the `CREATE_BREAKAWAY_FROM_JOB` flag for potential sandbox escapes. Passing `CREATE_BREAKAWAY_FROM_JOB` flag to `CreateProcess` should be done with care if [job objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects) are being used for sandboxing (e.g., for [UI restrictions](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_ui_restrictions) or [security limits](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_security_limit_information)). If a process in a job creates a new process with this flag, then the new process is created outside of the job and is no longer subject to the job's restrictions or lifetime, essentially "escaping" the sandbox.
  - Can you control the path, arguments, working directory, or environment variables to execute something else, or otherwise cause unexpected behavior?
  - Can you exploit the launched executable via DLL planting or other similar tricks?
  - What files, registry keys, and other resources does the launched process touch?
  - Does the new process communicate with the sandboxed processes in the job? If so, can you abuse bugs in that functionality to escape the sandbox?
- [ ] When processes are managed with [job objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects), check that the [job security descriptors](https://learn.microsoft.com/en-us/windows/win32/procthread/job-object-security-and-access-rights) are appropriate.
- [ ] Assess whether arguments to functions like `LoadLibrary`, `CreateProcess`, `CreateProcessAsUser`, [`ShellExecute`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecutea), [`ShellExecuteEx`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexa), and [`SHCreateProcessAsUser`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shcreateprocessasuserw) can be influenced by user input.
  - For example, if these functions are called with not-full path arguments, the attacker may plant an executable in CWD. See [CVE-2020-27955](https://legalhackers.com/advisories/Git-LFS-RCE-Exploit-CVE-2020-27955.html) for an example vulnerability.
- [ ] If manual signing or integrity checks are performed before calls to functions like `LoadLibrary`, `CreateProcess`, and `ShellExecute`, assess whether these checks are resistant to TOCTOU issues.
  - Manual signing checks on DLLs should be avoided; `LoadLibraryEx` with `LOAD_LIBRARY_REQUIRE_SIGNED_TARGET` should be used instead.
- [ ] Review the codebase for path traversal and confusion issues.
  - Are they canonicalizing paths before doing comparisons?
    - [`PathCchCanonicalizeEx`](https://learn.microsoft.com/en-us/windows/win32/api/pathcch/nf-pathcch-pathcchcanonicalizeex) should be used to find the canonical path for a given path string.
  - Are they handling strings in UTF-16 and using case-insensitive ordinal comparison?
    - Case-sensitive ordinal comparison (i.e., byte comparison, not character comparison) of UTF-16 paths is required.
    - Are they using `-A` suffixed APIs that take ANSI path strings (e.g., `CreateFileA`)? Windows attempts to perform character fitting on the names, but it may still result in [mojibake](https://en.wikipedia.org/wiki/Mojibake) when dealing with UTF-16 characters outside the basic ANSI set, potentially allowing you to bypass checks.
    - Are they incorrectly assuming the path string is ANSI/ASCII or UTF-8? Can you abuse this with Unicode paths? (e.g., ㍜ is UTF-16 codepoint 0x335C, which would be an exclamation mark followed by a backslash if interpreted as ASCII).
    - Look for [WorstFit](https://devco.re/blog/2025/01/09/worstfit-unveiling-hidden-transformers-in-windows-ansi/) style vulnerabilities.
  - Are they improperly normalizing paths?
    - What happens if you use a reserved path like LPT or COM? See [the fix for CVE-2025-27210](https://github.com/nodejs/node/pull/59286) for how this can be vulnerable.
    - If they are blocking those with a regex, can you evade it with superscript digits, as per [this issue](https://github.com/nodejs/node/pull/59261)?
  - Can you abuse reserved DOS device names to break file creation?
    - Files with reserved DOS device names cannot typically be created or accessed:
      `CON`, `PRN`, `AUX`, `NUL`, `COM1`, `COM2`, `COM3`, `COM4`, `COM5`, `COM6`, `COM7`, `COM8`, `COM9`, `COM¹`, `COM²`, `COM³`, `LPT1`, `LPT2`, `LPT3`, `LPT4`, `LPT5`, `LPT6`, `LPT7`, `LPT8`, `LPT9`, `LPT¹`, `LPT²`, and `LPT³` (the superscript numbers are ISO/IEC 8859-1 codepage characters).
    - These names are usually still reserved even if they are followed by an extension (e.g., `c:\users\test\COM3.log` is still reserved).
    - See the full details on [naming files](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file) on Windows.
  - Can symlinks or junctions be used to bypass path traversal checks?
    - Do they check the symlink/junction target? Is the check vulnerable to TOCTOU issues?
    - For further reading, see this [article on symlink exploits](https://nixhacker.com/understanding-and-exploiting-symbolic-link-in-windows/).
    - Consult the [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools) suite for tools you can use to test symlinks.
  - Are they defending against [special path formats](https://github.com/rust-lang/cargo/issues/9770#issuecomment-993069234)?
    - Are they defending against UNC paths?
      - Example: `\\server_or_ip\path\to\file.abc`
      - Example: `\\?\server_or_ip\path\to\file.abc`
      - [`PathIsNetworkPath`](https://learn.microsoft.com/en-gb/windows/win32/api/shlwapi/nf-shlwapi-pathisnetworkpathw) should be used to check if the target resource is a remote resource (UNC/SMB, FTP, etc.).
    - Are they defending against NT file paths?
      - Example: `\\.\GLOBALROOT\Device\HarddiskVolume1\` is the same as `C:\`.
    - Are they defending against [8.3 filenames](https://blog.0daylabs.com/2016/09/06/using-windows-shortfilename-feature-lfi/) (short filenames \[SFNs\])?
      - Example: `TextFile.Mine.txt` → `TEXTFI~1.TXT`
  - If you use the `FILE_FLAG_POSIX_SEMANTICS` flag with `CreateFile`, you can create multiple files with the same name but with different case sensitivity. This may be a useful gadget for attacking path handling.
    - While you can create directories with `CreateFile` by passing `FILE_ATTRIBUTE_DIRECTORY`, the POSIX semantics flag does not make them case-sensitive.
- [ ] Check if named pipes are used. Look for [`CreateNamedPipe`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea) and [`CallNamedPipe`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-callnamedpipea) calls, or a `CreateFile` call with a path that starts with `\\.\pipe\`.
  - When the pipe is created, is `lpSecurityAttributes` set to an appropriate security descriptor?
  - Can multiple connections be made to the pipe at once?
    - If so, is the state properly separated between the connections?
    - If not, can functionality be locked out by a malicious process connecting first?
  - Is the data that is passed through the pipe properly validated and sanitized?
  - The `PIPE_REJECT_REMOTE_CLIENTS` flag should be applied to the `dwPipeMode` argument during pipe creation in most cases, since networked named pipes are pretty unusual.
  - Named pipes can be enumerated with [PipeList](http://learn.microsoft.com/en-us/sysinternals/downloads/pipelist).
- [ ] Check for failure to initialize memory before use.
  - [`GlobalAlloc`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-globalalloc) does not zero (unless the `GMEM_ZEROINIT` flag is passed).
  - [`LocalAlloc`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-localalloc) does not zero (unless the `LMEM_ZEROINIT` flag is passed).
  - [`HeapAlloc`](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc) does not zero (unless the `HEAP_ZERO_MEMORY` flag is passed).
  - [`HeapReAlloc`](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heaprealloc) does not zero (unless the `HEAP_ZERO_MEMORY` flag is passed).
  - [`VirtualAlloc`](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) *does* zero, except for certain cases where the `MEM_RESET` and `MEM_RESET_UNDO` flags are used. See the docs for more info.
- [ ] Check for memory leaks.
  - Memory should be freed with the appropriate free function (`GlobalFree`, `LocalFree`, `HeapFree`, `VirtualFree`, etc.).
  - There is a risk of heap spraying if contents are user-controlled.
  - Sensitive data could persist in process memory.
  - For SSPI APIs on Windows, check which API should be used for freeing memory associated with credential data. For example, [`SspiEncodeAuthIdentityAsStrings`](https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-sspiencodeauthidentityasstrings) requires that you use [`SspiFreeAuthIdentity`](https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-sspifreeauthidentity) (which zeroes the internal backing memory before freeing it) rather than [`SspiLocalFree`](https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-sspilocalfree) (which is just a wrapper around `LocalFree`). The Windows SDK examples incorrectly use `SspiLocalFree` in a few places and people sometimes copy the examples rather than following what the MSDN docs say.
- [ ] Check whether in-process sensitive information is protected.
  - Use of `memset` and [`ZeroMemory`](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa366920\(v=vs.85\)) is inappropriate for zeroing sensitive information. `memset_s` or `RtlSecureZeroMemory` should be used instead to prevent the compiler from optimizing it out.
  - The Data Protection API (DPAPI) should be used for encrypting sensitive data in memory (via functions like [`CryptProtectMemory`](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectmemory)).
- [ ] Look for use of [`VirtualAllocEx`](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex), [`VirtualProtectEx`](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex), [`CreateRemoteThread`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread), [`ReadProcessMemory`](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory), and [`WriteProcessMemory`](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
  - These are used to mess with other processes (e.g., for remote DLL injection).
  - What processes are being injected into? What changes are made? Evaluate the functionality for increased attack surface.
  - Can you control the written address? Write-what-where into another process is a powerful primitive for code execution, either via executable memory overwrite or by overwriting pointers.
  - Check if the injection uses a fixed address (i.e., a specific address passed in `VirtualAllocEx`).
    - This can lead to a crash or memory corruption on ASLR-enabled processes since there is no guarantee that the fixed target address is not already in use.
    - Can you block injection into a process you control by allocating that address range first? This is particularly relevant for security software.
  - Is sensitive data written into the other process? If so, can you abuse it?
    - Are credentials, keys, and other sensitive data written into low-privilege processes?
    - Address or handle leaks might be useful as a leak primitive for memory corruption issues.
  - If memory is being written to another process, is the source buffer properly initialized? If not, this is a cross-process memory disclosure. Is there a chance that this memory contains sensitive information from the process performing the cross-process write?
  - Can you get the injection to be performed repeatedly?
    - If so, this constitutes a potential DoS condition from OOM.
    - If the data is predictable, this may be a potential heap spray gadget for exploiting processes with ASLR.
    - If the pages are executable, this may be abusable as an [ROP](https://en.wikipedia.org/wiki/Return-oriented_programming) spray gadget when exploiting processes with ASLR.
  - When another process's memory is read using `ReadProcessMemory`, is it validated properly? Can a malicious process being targeted trigger bugs in data-parsing logic?
- [ ] Look for [`AdjustTokenPrivileges`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges) calls, as these are almost always security-relevant.
  - If `SeBackupPrivilege` is enabled, the token can gain complete access to the filesystem with no permissions checks.
  - If `SeTcbPrivilege` is enabled, the token can create login tokens for other users with no additional checks.
  - If `SeAssignPrimaryTokenPrivilege` is enabled, the token can replace the primary security tokens on processes.
  - If `SeDebugPrivilege` is enabled, the token can bypass all discretionary access control lists (DACLs) and system access control lists (SACLs) on the system, essentially giving it carte blanche on the whole system.
  - See MSDN's [Enabling and Disabling Privileges in C++](https://learn.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--) for more info.
- [ ] Check the services' permissions to ensure they run with the minimum (e.g., using `LOCAL SERVICE` or `NETWORK SERVICE` instead of `SYSTEM`).
  - [icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls) is a useful tool for displaying ACLs.
- [ ] Check the service binaries to ensure they have an appropriate DACL and SACL on the binary and path.
  - DACLs should prevent regular users from writing files to that location.
    - If the service binary is not writeable but the directory is, DLL planting attacks can be used.
  - SACL should prevent low-integrity labels from touching anything.
- [ ] Check the service registry entries to ensure they have an appropriate DACL.
  - This is done automatically if the SCM APIs are used to register the service, but some applications manually add a service entry via registry APIs.
- [ ] If the application is a security product, check that it is registering itself as a [protected process](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-).
  - Recommend making the service process protected if tampering is a concern.
  - To debug protected processes, you will need to use WinDbg as a kernel debugger.
  - Does the protected process launch any non-protected child processes that perform sensitive operations such as updates?
  - Does the protected process have any facility to execute arbitrary code that has not been signed (e.g., JS or other scripting)? Does it load any DLLs with such capabilities? This is strongly recommended against, because it sidesteps the signing/integrity requirements associated with protected processes.
- [ ] Check whether the application installs any certificates into the [Windows Certificate Store](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/certificate-stores). If so, check whether they are appropriately restricted in purpose and whether you can modify certificates at rest during the certificate installation process.
  - Go to Start → Run → `certmgr.msc` to see certificate stores.
- [ ] Look for use of deprecated cryptography APIs.
  - Cryptographic service provider (CSP) APIs starting with Crypt (e.g., `CryptGenRandom`, `CryptAcquireContext`, etc.) are deprecated. The [Cryptography API: Next Generation (CNG) APIs](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal) should be used instead.
- [ ] Look for use of insecure cryptographic primitives.
  - If the old CSP APIs are in use, check the [`ALG_ID`](https://learn.microsoft.com/en-us/windows/win32/seccrypto/alg-id) value on functions like [`CryptCreateHash`](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptcreatehash) and [`CryptGenKey`](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptgenkey).
  - If the newer CNG APIs are in use, take these steps:
    - Check for [`BCryptOpenAlgorithmProvider`](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptopenalgorithmprovider) calls; [CNG algorithm identifiers](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers) are passed as strings.
    - For most other CNG APIs, check for [CNG algorithm pseudo-handles](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-pseudo-handles), which are used to specify the algorithm.
- [ ] Review the codebase for vulnerabilities to a heap leak with `fwrite` of size 1\. See [this X post](https://x.com/gamozolabs/status/1207088312273362945) for more details.

## Windows kernel

- [ ] Run CodeQL on the application's driver. Microsoft has published [CodeQL support and security query packs for Windows drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/static-tools-and-codeql?tabs=whcp%2Clatest).
  - If you can build the driver from source, CodeQL is a high-value SAST approach.
  - If you *cannot* build the driver from source, you may still be able to run CodeQL with `--build-mode=none` on the CodeQL CLI during database creation, but coverage and accuracy will be significantly diminished.
- [ ] Run [Driver Verifier](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/driver-verifier) against the driver binary to test it for issues.
  - Ideally, do this in a VM with WinDbg attached from outside (e.g., [debugging via a virtual COM port](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/attaching-to-a-virtual-machine--kernel-mode-)) so that you can capture info about where crashes occur.
- [ ] Run [BinSkim](https://github.com/microsoft/binskim) to check mitigation opt-in and other issues in the driver binary.
  - DEP (NX) support should be enabled.
  - Forced integrity checking (`IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY`) should be enabled to prevent unsigned binaries being loaded by the driver.
  - Note that [old drivers built pre-VS2015 will have the `INIT` section marked as RWX and discardable](https://blog.poly.nomial.co.uk/2015-09-03-wx-policy-violation-affecting-all-windows-drivers-compiled-in-visual-studio-2013-and-previous.html). This is generally harmless as the `INIT` section is unmapped after `DriverEntry` returns, but it is a good indication that the driver was built with a very old toolchain (this was fixed in VS2015).
- [ ] Check uses of [`InitializeObjectAttributes`](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/nf-ntdef-initializeobjectattributes), the primary macro used to set up object attributes and security descriptors. This is widely relevant.
  - Ensure that `OBJ_KERNEL_HANDLE` is passed if the created object should only be accessed within the kernel.
  - If a security descriptor is passed (last argument), check that it is appropriate.
  - If a security descriptor is not passed (last argument is `NULL`), this will create the object with the default security descriptor.
    - On Windows 8.1 and prior, many system object namespaces (e.g., symlinks) have no inheritable ACEs by default, so a `NULL` security descriptor means the object is accessible by everyone unless the local security policy "[System objects: Strengthen default permissions of internal system objects (for example, Symbolic Links)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/system-objects-strengthen-default-permissions-of-internal-system-objects)" is manually enabled on the system.
    - On Windows 10 and later, the above local security policy is enabled by default, adding inheritable ACEs for read-only access by normal users and read-write-modify access by administrators. Therefore, a `NULL` descriptor will cause the object to be read-accessible by regular users and fully accessible by admins.
- [ ] Check that the `OBJ_KERNEL_HANDLE` flag is passed as part of the object attributes where a handle is created that should be accessible only within the kernel (e.g., within a driver or shared between drivers, not accessed from a usermode process). The following APIs are common examples that create handles where this issue is relevant:
  - Files: `IoCreateFile`, `ZwCreateFile`, `ZwOpenFile`
  - Registries: `IoOpenDeviceInterfaceRegistryKey`, `IoOpenDeviceRegistryKey`, `ZwCreateKey`, `ZwOpenKey`
  - Threads: `PsCreateSystemThread`
  - Events: `IoCreateSynchronizationEvent`, `IoCreateNotificationEvent`
  - Symlinks: `ZwOpenSymbolicLinkObject`
  - Directory objects: `ZwCreateDirectoryObject`
  - Section objects: `ZwOpenSection`
- [ ] Look for any general issues around [`IoCreateDevice`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocreatedevice) and [`IoCreateDeviceSecure`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdmsec/nf-wdmsec-wdmlibiocreatedevicesecure).
  - The device name should be null; usually the driver should be unnamed and the symlink (if one is created) should be the item that is named.
  - The `DeviceCharacteristics` argument should include the `FILE_DEVICE_SECURE_OPEN` flag.
  - `IoCreateDeviceSecure` should be used instead of `IoCreateDevice`.
  - If `IoCreateDeviceSecure` is used, check that the `DefaultSDDLString` SDDL (security descriptor) string is appropriate.
    - Alternatively, the device model or device setup class should have its [SDDL set in the registry via the INF file or setup APIs](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/setting-device-object-properties-in-the-registry).
  - If `IoCreateDeviceSecure` is used, check that `DeviceClassGuid` is generated or otherwise unique, not an existing or shared GUID.
- [ ] Look for any general issues with [`IoCreateSymbolicLink`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocreatesymboliclink).
  - The `SymbolicLinkName` argument tells you the name of the symlink. It will appear in the `\GLOBAL??` object namespace in [WinObj](https://learn.microsoft.com/en-us/sysinternals/downloads/winobj).
  - A named symlink to a device should not be created unless necessary (e.g., for interoperability with a usermode application).
  - Check that the DACL is appropriate.
- [ ] Find the `DriverEntry` function, check which dispatch routines are set in the `MajorFunction` property of the driver object, and evaluate their security impact. Almost all dispatch routines create some external attack surface, so they are all important to evaluate, but here are some other common dispatch routines of interest:
  - `IRP_MJ_READ` and `IRP_MJ_WRITE` handle `ReadFile` and `WriteFile` calls, respectively, on the driver object.
  - `IRP_MJ_DEVICE_CONTROL` handles `DeviceIoControl` calls on the driver object.
  - [WMI requests](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/handling-wmi-requests) are dispatched to `IRP_MJ_SYSTEM_CONTROL`.
- [ ] If there is an `IRP_MJ_DEVICE_CONTROL` dispatch routine, check each IOCTL's functionality for security impact.
- [ ] Check that the `Access` (`RequiredAccess`) field is set appropriately for each IOCTL (e.g., `FILE_WRITE_DATA` to restrict access to the IOCTL to callers that have write access to the driver).
  - [`IoValidateDeviceIoControlAccess`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iovalidatedeviceiocontrolaccess) can be used in the IOCTL handler to implement stricter checks.
- [ ] Check for buffer overruns in IRP dispatch routines.
  - Accesses to `Irp->AssociatedIrp.SystemBuffer` must respect the lengths provided in `Parameters.DeviceIoControl.InputBufferLength` and `OutputBufferLength`.
- [ ] Where output buffers are used, ensure that the `SystemBuffer` is zeroed.
  - Not zeroing the `SystemBuffer` leads to kernel memory disclosure and undefined behavior.
  - See MSDN's [Failure to Initialize Output Buffers](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/failure-to-initialize-output-buffers) for more information.
- [ ] Review calls to [`MmGetSystemAddressForMdlSafe`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmgetsystemaddressformdlsafe) to ensure they check for `NULL`.
- [ ] Where a path to an object (e.g. file, registry key, section, mutex, semaphore, event, etc.) is passed from an untrusted context (e.g. usermode) to the kernel, check whether the caller's permissions and privileges are checked.
  - If not, look for potential [confused deputy attacks](https://en.wikipedia.org/wiki/Confused_deputy_problem).
- [ ] If a function can be reached from both kernelmode and usermode callers, is [ExGetPreviousMode](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exgetpreviousmode) used to check whether the call came from usermode or kernelmode?
  - More details are available in the [PreviousMode](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/previousmode) documentation.
- [ ] Where event, mutex, semaphore, and timer synchronization objects are created or opened, check that they are done so securely.
  - Check the DACL with WinObj when the object is named (this usually appears in `BaseNamedObjects`); if a null security descriptor is passed, it will inherit the ACEs of the object namespace, if any (see the `InitializeObjectAttributes` information above).
  - These objects should not be created in the context of a usermode thread (e.g., in an IOCTL dispatch) unless they are intended to be shared with that process.
  - If a named synchronization object is created, check that `OBJ_PERMANENT` is passed in the object attributes to prevent it from being freed by usermode. [`ZwMakeTemporaryObject`](http://ZwMakeTemporaryObject) can be called from kernelmode to free it later.
  - If a handle to a non-permanent synchronization object is passed to usermode (e.g., in an IOCTL response), then [`ObReferenceObjectByHandle`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obreferenceobjectbyhandle) must be used to increment the refcount on the object to prevent the usermode thread from deleting the object by closing the handle. The reference should be stored in the driver device's extension.
- [ ] Look for cases where [`KeWaitForSingleObject`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kewaitforsingleobject) and [`KeWaitForMultipleObjects`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kewaitformultipleobjects) wait on synchronization objects (event, mutex, semaphore, timer) that are accessible to or shared with usermode.
  - Can these functions deadlock the kernel thread by acquiring locks permanently or in the wrong order? Calls that pass `NULL` to the `Timeout` argument are at high risk since they block forever if the synchronization object is never released.
  - Can a usermode process block important functionality from running by acquiring a sync object and never releasing it?
  - Are error codes checked and handled properly?
- [ ] Where section objects (shared memory regions) are created or opened, check that they are done so securely.
  - Check the DACL with WinObj when the section is named (this usually appears in `BaseNamedObjects`); if null is passed, it will inherit the ACEs of the object namespace, if any (see the `InitializeObjectAttributes` information above).
  - Section objects created in usermode (e.g., by [`CreateFileMapping`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga)) must not be mapped by the kernel. The section must be created and mapped in the kernel.
  - Section objects should not be opened using a handle provided from usermode.
  - When a section must not be accessible outside of the kernel, it should not be mapped in a usermode thread context (e.g., in a dispatch routine for an IOCTL).
  - If a named section object is created, `OBJ_PERMANENT` should be passed in the object attributes to prevent it from being unmapped by usermode. [`ZwMakeTemporaryObject`](http://ZwMakeTemporaryObject) can be called from kernelmode to unmap it later.
- [ ] Where mapped section objects are accessed, check that they are done so safely.
  - Data in sections must be validated and treated as untrusted (especially if it is shared with usermode).
  - Check for TOCTOU and other race conditions; data in a section may be changed at any time. Ideally, data should be copied to kernel memory first and then processed.
  - Accesses should be wrapped in try/catch statements to prevent DoS.
  - If a handle to a non-permanent section object is passed to usermode (e.g., in an IOCTL response), then [`ObReferenceObjectByHandle`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obreferenceobjectbyhandle) must be used to increment the refcount on the object to prevent the usermode thread from deleting the object by closing the handle. The reference should be stored in the driver device's extension.
- [ ] Check that kernel addresses are not leaked in data written to sections that are usermode-accessible.
  - Kernel object handles may be opaque wrappers around kernel addresses.
- [ ] Check whether handles are passed between usermode and kernelmode.
  - Usermode-to-kernelmode handle passing is really dangerous; handles should be created on the kernel side and passed to usermode.
  - Usermode-to-kernelmode handle passing can result in handle confusion. Can you pass the wrong type of handle (e.g., a mutex handle when a file handle is expected)?
- [ ] Look for calls to [`ZwSetSecurityObject`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwsetsecurityobject). Such calls can often be a sign of a race condition.
  - Ideally, the `InitializeObjectAttributes` macro should be used to set a security descriptor as part of the object attributes during creation, rather than securing the object after creation.
- [ ] Check memory accesses around regions acquired by [`MmProbeAndLockPages`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmprobeandlockpages) and [`MmProbeAndLockSelectedPages`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmprobeandlockselectedpages) calls. These are typically used to map usermode memory into kernel space for [DMA](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-direct-i-o-with-dma) or [PIO](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-direct-i-o-with-pio) operations.
  - Ensure [`ProbeForRead`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-probeforread) is used to check that the memory region is readable before it is accessed.
  - Ensure that data mapped from usermode is properly validated.
  - Ensure accesses are wrapped in try/catch statements.
  - Look for TOCTOU issues.
- [ ] Check that [`MmSecureVirtualMemory`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-mmsecurevirtualmemory) is used to help prevent TOCTOU issues on page protection when accessing usermode memory directly. Also check that usermode memory accesses are wrapped in try/catch statements to account for edge cases.
- [ ] Look for calls to [`MmIsAddressValid`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-mmisaddressvalid) that may indicate insufficiently robust memory access patterns.
  - This is an older function. Generally, we want `ProbeForRead` and `__try`/`__except`, plus `MmSecureVirtualMemory` where appropriate.
  - See MSDN's [Buffer Handling](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/buffer-handling) for more info.
- [ ] Look for uses of `POOL_FLAG_NON_PAGED_EXECUTE` on memory allocations and evaluate their security impact, as RWX memory in the kernel is risky.
- [ ] Look for uses of memory allocation APIs and ensure they do not take a size argument based on untrusted input without validation (same as passing arbitrary size to `malloc`). The following are common examples of allocation APIs:
  - `ExAllocatePool`, `ExAllocatePoolWithTag`, `ExAllocatePoolWithQuota`, `ExAllocatePoolWithQuotaTag`, `ExAllocatePoolWithTagPriority`, `ExAllocatePool2`, `ExAllocatePool3`
  - `MmAllocateContiguousMemory`, `MmAllocateContiguousMemoryEx`, `MmAllocateContiguousMemorySpecifyCache`, `MmAllocateContiguousMemorySpecifyCacheNode`, `MmAllocateContiguousNodeMemory`
  - `MmAllocateNonCachedMemory`
  - `AllocateCommonBuffer`
- [ ] Check that an NX [`POOL_TYPE`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_pool_type) is used when allocating pool memory (e.g., `NonPagedPoolNx` or `NonPagedPoolNxCacheAligned`).
- [ ] Check that the memory allocations and frees are performed with matching APIs, and that the appropriate free function is used when memory is allocated internally within an API.
  - For example, if memory is allocated with `ExAllocatePoolWithTag`, then it should be freed with `ExFreePoolWithTag`. Deallocation with the wrong API may cause kernel heap corruption or a bugcheck. Refer to the MSDN documentation for each memory allocation API to find the correct deallocation function.
  - Many LSA functions that allocate memory internally require [`LsaFreeMemory`](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsafreememory) to be used for deallocation.
- [ ] Check that memory is zeroed before use and that outdated allocation functions are not used.
  - `ExAllocatePool`, `ExAllocatePoolWithTag`, `ExAllocatePoolWithQuota`, `ExAllocatePoolWithQuotaTag`, and `ExAllocatePoolWithTagPriority` [should be replaced with `ExAllocatePool2` and `ExAllocatePool3`](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/updating-deprecated-exallocatepool-calls), as these new functions automatically zero memory during the allocation to prevent memory disclosure issues.
  - Memory from other allocation functions should be zeroed first.
- [ ] Check that [`RtlSecureZeroMemory`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlsecurezeromemory) is used to zero memory, not `RtlZeroMemory`.
- [ ] Look for [`IoGetRemainingStackSize` and `IoGetStackLimits`](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-the-kernel-stack) calls.
  - These are usually code smells (e.g., messing with kernel stacks or dynamic allocation in the stack) that can lead to DoS or other bugs if done wrong.
- [ ] Look for [`IoWithinStackLimits`](http://IoWithinStackLimits) calls.
  - These can be indicators that the code is doing something unusual with stack buffers, with the potential for errors that lead to bad accesses.
- [ ] Look for TOCTOU issues in filesystem and registry API usage.
  - Look for uses of `ZwOpenDirectoryObject` or `ZwQueryDirectoryFile` to enumerate directory contents, followed by `ZwOpenFile` or `ZwCreateFile` to open the file without checking the call's success to ensure that the file still exists.
  - Look for uses of `ZwEnumerateKey` to enumerate registry key contents, followed by `ZwOpenKey` to open a subkey without checking the call's success to ensure that the key still exists.
  - Look for uses of `ZwReadFile` without checking that file contents did not change in between calls.
- [ ] Look for usage of [spinlocks](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-spin-locks) that might be abused for denial of service.
  - Ensure that acquired spinlocks are released on all code flow paths, including cases where an exception might occur.
  - Ensure that code safeguards against excessive computation or long delays while a spinlock is acquired. A kernel thread that hangs waiting for a spinlock will consume a lot of CPU time and may trigger a `THREAD_STUCK_IN_DEVICE_DRIVER` bugcheck.
  - Look for cases where spinlock contention can be intentionally caused by a malicious usermode process, such as by repeatedly triggering an IOCTL that acquires the spinlock, resulting in system threads locking up or preventing important operations from being processed.
- [ ] Look for interesting notify routines such as the following. These are commonly used by AV/EDR.
  - `PsSetCreateProcessNotifyRoutine(Ex/Ex2)`
  - `PsSetCreateThreadNotifyRoutine(Ex)`
  - `PsSetLoadImageNotifyRoutine(Ex)`
- [ ] Look for uses of `RtlCopyString` or `RtlCopyUnicodeString` without verifying that the string being copied into has a large enough `MaximumLength`.
  - This does not lead to a buffer overflow, since these functions respect the `MaximumLength` field in the target string, but it does silently truncate the string.
- [ ] Look for instances in which the result of [`RtlAppendUnicodeToString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlappendunicodetostring) or [`RtlAppendUnicodeStringToString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlappendunicodestringtostring) is not checked.
  - These return `STATUS_BUFFER_TOO_SMALL` if the target string's backing buffer is not large enough to store the resulting string. If the return value is not checked, the string may not contain the expected value.
- [ ] Look for calls to [`SeAccessCheck`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-seaccesscheck).
  - These are always security-relevant as they mean the driver is doing its own checks to see if a user has access to something.
- [ ] Look for calls to [`SeAssignSecurity`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-seassignsecurity) and [`SeAssignSecurityEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-seassignsecurityex).
  - These alter ACEs on security descriptors and are, therefore, always security-relevant.
- [ ] Look for calls to [`RtlQueryRegistryValues`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues).
  - Ensure that the `RTL_QUERY_REGISTRY_NOEXPAND` flag is passed when a `REG_EXPAND_SZ` or `REG_MULTI_SZ` value type might be read. This prevents unsafe expansion of environment variables from within the kernelmode context.
  - Ensure that the `RTL_QUERY_REGISTRY_TYPECHECK` flag is passed when using the `RTL_QUERY_REGISTRY_DIRECT` flag. This causes the API call to safely fail when the target value type does not match the expected type, thus avoiding a buffer overflow.
- [ ] Check if the driver implements `IRP_MJ_POWER` for power management events.
  - Does it reset or recreate any objects or state on sleep and resume? Can this be abused?
  - Does it incorrectly expect that external system information will remain identical after resuming from a low-power state (e.g., sleep or hibernate)? Can this be abused?
- [ ] Assess whether the code assumes that [`KeQuerySystemTime`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kequerysystemtime-r1) (or the `Precise` variant) is monotonic.
  - Can you bypass rate limits and other time-related checks if the system clock changes (e.g., at a DST boundary)?
- [ ] Assess the attack surface of WMI functionality, if the driver registers as a WMI provider.
  - Drivers that act as WMI providers will call the [`IoWMIRegistrationControl`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iowmiregistrationcontrol) API; see [MSDN's Registering as a WMI Data Provider](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/registering-as-a-wmi-data-provider) for more information.
  - Most of the attack surface will arise from code that handles the [WMI minor IRPs](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/wmi-minor-irps), although KMDF drivers use [alternative callback APIs](https://learn.microsoft.com/en-us/windows-hardware/drivers/wdf/introduction-to-wmi-for-kmdf-drivers).
  - Ensure that sensitive information is not exposed in WMI data.
- [ ] Assess the use of event tracing (ETW).
  - Event provider registration can be identified by finding [`EtwRegister`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-etwregister) call sites. Event writes can be identified by finding [`EtwWrite`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-etwwrite), [`EtwWriteEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-etwwriteex), [`EtwWriteString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-etwwritestring), and [`EtwWriteTransfer`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-etwwritetransfer) call sites.
  - Ensure that sensitive information is not exposed in ETW messages.
  - Ensure that channels are configured with appropriate access controls and isolation. This is typically configured in the `isolation` property of the [`ChannelType`](https://learn.microsoft.com/en-us/windows/win32/wes/eventmanifestschema-channeltype-complextype) definition in the instrumentation manifest for the driver at build time. See [MSDN's Adding Event Tracing to Kernel-Mode Drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/adding-event-tracing-to-kernel-mode-drivers) for details.
    - Usermode applications may also use the [`EvtSetChannelConfigProperty`](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtsetchannelconfigproperty) API to configure the [`EvtChannelConfigIsolation`](https://learn.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_channel_config_property_id) property with a value from the [`EVT_CHANNEL_ISOLATION_TYPE`](https://learn.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_channel_isolation_type) enum.
  - Read [our blog post on ETW internals](https://blog.trailofbits.com/2023/11/22/etw-internals-for-security-research-and-forensics/) for information on finding provider GUIDs and event-consuming applications.
  - [Geoff Chappell's ETW Security page](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/secure/index.htm?tx=32,35) contains further useful information on the securable objects used in ETW.
- [ ] If the driver is for a PCIe device (including Thunderbolt, USB4, M.2, U.2, and U.3), verify that the driver [opts into DMA remapping](https://learn.microsoft.com/en-us/windows-hardware/drivers/pci/enabling-dma-remapping-for-device-drivers).

## Seccomp

[Sandboxing is hard](https://www.youtube.com/watch?v=gJpaxisyQfY). But if it is needed and seccomp is used, ensure the following is done:

- [ ] The BPF filter [checks the architecture](https://man7.org/linux/man-pages/man2/seccomp.2.html#:~:text=Because%20numbering%20of%20system%20calls%20varies%20between%20architectures%20and) (e.g., `x86-64` versus `i386`).
- [ ] The BPF filter [checks the ABI/calling convention](https://man7.org/linux/man-pages/man2/seccomp.2.html#:~:text=The%20arch%20field%20is%20not%20unique%20for%20all%20calling%20conventions.) (e.g., `x86-64` versus `x32` ABIs for `x86-64` architecture).
  - This means checking for syscalls with numbers greater than `0x40000000` (the `__X32_SYSCALL_BIT` flag).
- [ ] Syscalls [implemented in `vsyscall` and `VDSO` are handled correctly](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html#caveats).
  - This is important only for optimized syscalls like `gettimeofday`, `time`, `getcpu`, and `clock_gettime`.
  - Seccomp interaction with `VDSO` requires further research.
- [ ] [`io_uring` syscalls are blocked](https://manpages.debian.org/unstable/liburing-dev/io_uring_setup.2.en.html).
  - These syscalls allow programs to execute some syscalls without the BPF filter noticing them. Note that [Docker blocks `io_uring` syscalls by default](https://github.com/moby/moby/pull/46762).
- [ ] All semantically equivalent syscalls are handled in the same way (e.g., `chmod`, `fchmod`, `fchmodat`, `fchmodat2`; `seccomp`, and `prctl(PR_SET_SECCOMP)`).
  - Consult the [kernel's syscall tables](https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl).
- [ ] Syscalls enabling code execution in the kernel (e.g., `kexec_file_load`, `finit_module`) are prevented.
  - A malicious kernel module can easily manipulate the seccomp sandbox.
- [ ] If any of the following syscalls are blocked or traced, [then the `restart_syscall` syscall is also blocked or traced](https://git.causa-arcana.com/kotovalexarian-likes-github/moby--moby/commit/5abd881883883a132f96f8adb1b07b5545af452b?style=unified&whitespace=show-all&show-outdated): `poll`, `nanosleep`, `clock_nanosleep`, or `futex`.
- [ ] Old kernel versions are supported if needed:
  - [ ] For Linux kernel versions prior to 5.4, the BPF filter [checks for `compat` syscalls confusion](https://man7.org/linux/man-pages/man2/seccomp.2.html#:~:text=Additionally%2C%20kernels%20prior%20to%20Linux%205.4%20incorrectly%20permitted%20nr) (i.e., calling 64-bit ABI syscalls with the `__X32_SYSCALL_BIT` bit).
  - [ ] For Linux kernel versions prior to 4.8, the BPF filter [disables the use of `ptrace` for all sandboxed processes](https://www.exploit-db.com/exploits/46434).
  - [ ] For ancient Linux kernel versions, the sandbox [blocks access to the `/proc` filesystem](https://lkml.indiana.edu/hypermail/linux/kernel/0706.1/2525.html) instead of seccomp-related syscalls.
  - [ ] The Android LG kernel's [buggy `sys_set_media_ext` syscall is handled correctly](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/sandbox/linux/seccomp-bpf/sandbox_bpf.cc#59).
- [ ] If special handling of syscalls is needed (not simply allow/disallow), then mechanisms like [landlock](https://docs.kernel.org/userspace-api/landlock.html) or [namespaces](https://man7.org/linux/man-pages/man7/namespaces.7.html) are used.
- [ ] If special handling of syscalls is needed and seccomp must be used for the task, then the `SECCOMP_SET_MODE_FILTER` option is used with `SECCOMP_RET_TRACE` actions and `ptrace`.
  - [ ] `SECCOMP_SET_MODE_FILTER` is not used with `SECCOMP_FILTER_FLAG_NEW_LISTENER` and `seccomp_unotify`. This mechanism is inherently insecure. Consult the [`seccomp_unotify` man page](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html).
  - [ ] A similar [syscall user dispatch mechanism](https://www.kernel.org/doc/html/v6.1/admin-guide/syscall-user-dispatch.html) is also inherently insecure.
  - [ ] The `SECCOMP_RET_USER_NOTIF` actions have precedence over the `SECCOMP_RET_TRACE` actions: after the seccomp sandbox is enabled, addition of `SECCOMP_RET_USER_NOTIF` must not be allowed. The most secure solution is to forbid `seccomp` and `prctl(PR_SET_SECCOMP)` altogether.
  - [ ] The checklist on BPF filter handlers and `ptrace` below is consulted.

### BPF filter handlers and ptrace

If the seccomp filter uses the `SECCOMP_RET_TRACE` action, then all BPF filter handlers must be reviewed. These handlers are usually implemented in a process (the "tracer") that is tracing the sandboxed process (the "tracee") with the `ptrace` mechanism. Ensure that the following is done.

- [ ] All `ptrace` tracing options (e.g., `PTRACE_O_TRACEFORK`, `PTRACE_O_TRACECLONE`, etc.) are used on the tracee.
  - Otherwise, the tracee may escape the sandbox by creating child processes and calling `execve`.
- [ ] The `PTRACE_O_EXITKILL` is set on all sandboxed processes.
  - Otherwise, a crash of the tracer process allows malicious processes to trace sandboxed tracees and handle all `SECCOMP_RET_TRACE` actions (`ptrace-stop` events).
- [ ] Syscalls that the tracee may use to impact the tracer are forbidden:
  - `rt_sigqueueinfo` and `rt_tgsigqueueinfo` with any tracer's TID
  - `kill`, `tgkill`, and `tkill` with any tracer's TID
  - `setpriority`, `sched_{setaffinity,setattr,setparam,setscheduler}`, and `prlimit64` with any tracer's TID
  - `process_vm{writev,readv}` with any tracer's TID
  - `open`, `rename`, and other similar syscalls on `/proc/<tracer-pid>` and `/proc/<tracer-pid>/task/<tracer-tid>`
- [ ] [The correct syscall table is used](https://github.com/strace/strace/issues/103) to determine which syscall caused the `ptrace-stop` event.
  - This information is not provided in the event.
  - To determine the syscall number, the tracer can do the following:
    - Use `PTRACE_GET_SYSCALL_INFO` in new kernels
    - Read registers (e.g., with `PTRACE_GETREGSET`) and check the following in old kernels (this is a bit tricky and is often prone to TOCTOU bugs):
      - Bitness of registers (`RAX` versus `EAX`)
      - Instruction used to execute the syscall (the `int 0x80` and `sysenter` instructions in x64 use x86's table, and `syscall` uses x64's table)
      - CS register flags
      - Use of the `vsyscall` mechanism (`RIP & ~0x0C00 == 0xFFFFFFFFFF600000`)
        - If used, then finding the executed instruction is more complicated; the stack needs to be parsed to find the saved RIP.
  - The kernel downcasts syscall numbers to ints ([at least modern kernels do](https://elixir.bootlin.com/linux/v6.13.3/source/arch/x86/entry/entry_64.S#L113-L121), both for 64-bit and 32-bit syscall tables), and the BPF filter should use 32-bit opcodes for syscall numbers.
- [ ] Handlers interpret arguments (registers) according to the ABI ([values may be silently truncated](https://man7.org/linux/man-pages/man2/seccomp.2.html#:~:text=When%20checking%20values%20from%20args%2C%20keep%20in%20mind%20that%20arguments%20are)).
  - Both the BPF filter and a handler should be in agreement on arguments' bitness. Check [BPF opcode docs](https://www.kernel.org/doc/html/v5.17/bpf/instruction-set.html) to establish bitness.
- [ ] Memory-level race conditions are dealt with.
  - If the tracer reads the tracee's memory, then the memory could have been asynchronously modified by another thread (within a single thread group or process) or by another process (if some memory was explicitly shared). It is hard to fix this race condition completely.
  - For a single process, this race condition can be fixed by pausing all other threads of the tracee when the syscall entry hook is called and unfreezing them on syscall exit. It is possible to pause a group of tasks (processes or threads) using the cgroups (control groups) Linux kernel feature. In [cgroups v1, the freezer controller/subsystem](https://docs.kernel.org/admin-guide/cgroup-v1/freezer-subsystem.html) can be used to do so. In [cgroups v2, the `cgroup.freeze` file](https://docs.kernel.org/admin-guide/cgroup-v2.html) can be written to in order to freeze all tasks within a cgroup (and tasks in all descendant cgroups). We also recommend reading the [Thread Granularity section of the cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html#thread-granularity).
  - To protect against shared memory race conditions, the tracer would have to freeze all processes that the memory map was shared with. Alternatively, the memory could be exclusively locked (assuming it cannot be unlocked by other processes; this solution would need further investigation).
  - The [`userfaultfd`](https://man7.org/linux/man-pages/man2/userfaultfd.2.html) syscall [enables attackers to win races with 100% reliability](https://github.com/rexguowork/phantom-attack/blob/main/phantom_v1/attack_openat.c#L238).
- [ ] Operating-system-level race conditions are dealt with.
  - All the common vulnerabilities apply here, such as changing file paths with symlinks, and changing the tracee's resources, like the current working directory, environment variables, and file descriptors (or anything under `/proc/<pid>`).
  - Note that the two race conditions above can happen inside a handler execution but also during handler versus kernel execution (inside a syscall).
- [ ] If a syscall should be dropped (skipped), it is done in `syscall-enter-stop` (or `ptrace-stop`), not in `syscall-exit-stop`. The `syscall-exit-stop` event occurs after the syscall is executed, so even if the syscall's return value is modified to indicate an error in that stop, the syscall has already executed and its effects cannot be undone.
- [ ] If the tracee should be killed in a handler, it is done with `SIGKILL` (i.e., it is terminated immediately) and not by any delayed mechanism that would allow the tracee to execute after the handler returns but before the termination.
- [ ] Signals and `ptrace` events are correctly handled.
  - [ ] The [`syscall-enter-stop` and `syscall-exit-stop`](https://man7.org/linux/man-pages/man2/ptrace.2.html#:~:text=If%20the%20tracee%20was%20restarted%20by%20PTRACE_SYSCALL%20or%20PTRACE_SYSEMU) events must be correctly tracked by the tracer. The `ptrace` API does not provide a means to differentiate between these two. A common exploit is to manually send a `SIGTRAP` signal to the tracee or to make the tracee execute `int 3` (the software interrupt instruction) to confuse the handlers. A common solution is to use the `PTRACE_O_TRACESYSGOOD` option: it allows the tracer to easily differentiate between `syscal-{enter,exit}-stop` and other `stop` commands.
  - [ ] `SIGKILL` can terminate a process abruptly, and that event must be handled correctly.
    - The `syscall-exit-stop` event may not be delivered after syscall execution. Tracing of syscalls should start within `syscall-enter-stop` and end within either `syscall-exit-stop` or the tracee's exit event. Otherwise, an executed syscall can be missed by the tracer.
    - According to the [`ptrace` man page](https://man7.org/linux/man-pages/man2/ptrace.2.html#:~:text=The%20tracer%20cannot%20assume%20that%20the%20ptrace%2Dstopped%20tracee%20exists), "the tracer cannot assume that the ptrace-stopped tracee exists."
    - The `PTRACE_EVENT_EXIT` event may or may not be delivered after `SIGKILL`, [depending on kernel version](https://man7.org/linux/man-pages/man2/ptrace.2.html#:~:text=depending%20on%20the%0A%20%20%20%20%20%20%20kernel%20version%3B%20see%20BUGS%20below).
  - [ ] A signal with `WIFEXITED(status)` and `WIFSIGNALED(status)` [is not always delivered upon tracee termination](https://github.com/facebookexperimental/reverie/issues/15). For example, it is not delivered when a thread (that is not thread group leader) calls `execve`. The tracer should additionally use `PTRACE_EVENT_EXEC` to detect all possible tracee terminations.
  - [ ] When a new process is forked or cloned, then `PTRACE_EVENT_CLONE` (for the parent) and `PTRACE_EVENT_STOP` (for the child) signals are delivered simultaneously in undetermined order. This behavior may enable race condition bugs.
- [ ] The `clone` syscall with the `CLONE_UNTRACED` flag is not allowed.
  - This flag allows the tracee to clone in a way that the child is not traced by the original tracer. The tracee can then attach to the new thread via `ptrace` and handle all the `SECCOMP_RET_TRACE` actions (effectively disabling relevant seccomp filters). Note that this trick does not work for seccomp actions that explicitly drop syscalls (like `SECCOMP_RET_ERRNO`)—these are still blocked. To prevent this vulnerability, the following must be done:
    - Handle the `clone` syscall and remove the flag in the `ptrace-stop` event or block `clone` with the flag (blocking should be implemented in BPF, as it is less error-prone).
      - The `clone3` syscall must be blocked and [its return value must be set to `ENOSYS`](https://github.com/moby/moby/commit/9f6b562d). This syscall stores arguments in memory and cannot be inspected in the BPF filter; a `ptrace` handler would be vulnerable to TOCTOU attacks. `ENOSYS` error makes programs fall back to using `clone`.
    - Note that the kernel [may have reversed the order of `clone` arguments](https://www.kernelconfig.io/config_clone_backwards3) (the `CONFIG_CLONE_BACKWARDS*` configurations; consult the [Flatpack seccomp implementation](https://github.com/flatpak/flatpak/blob/9766ee05b1425db397d2cf23afd24c7f6146a69f/common/flatpak-run.c#L2937-L2944)).
- [ ] If the tracer uses `PTRACE_PEEK*` `ptrace` calls, then errors are handled correctly: the `errno` must be consulted, not the return value.
- [ ] Return values of the tracer's calls to `ptrace(ATTACH/SEIZE)` are checked.
  - An error means there is no effective sandboxing, as a malicious process may then try to attach to the tracee.
  - Note that the tracee (or the malicious process) may try to force an error in multiple ways, such as by using `prctl(PR_SET_PTRACER)` or `prctl(PR_SET_DUMPABLE, 0)`, or by changing the YAMA policy (`/proc/sys/kernel/yama/ptrace_scope`).
- [ ] Syscalls executed via the `vsyscall` mechanism are handled correctly.
  - Such syscalls [cannot be dynamically replaced, only dropped](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html#caveats).
- [ ] The following obscure syscalls are blocked, if possible. While these syscalls should not enable seccomp bypasses, they usually should be blocked "just in case" and because they can be abused to circumvent filters for other syscalls:
  - [`modify_ldt`](https://github.com/flatpak/flatpak/issues/4297)
  - `uselib`
  - [Filesystem-manipulating syscalls](https://github.com/flatpak/flatpak/security/advisories/GHSA-67h7-w3jq-vh4q) (`chroot`, `pivot_root`, `mount`, `move_mount`, `open_tree`, `fsopen`, `fsmount`)
  - [VM/NUMA ops](https://github.com/flatpak/flatpak/blob/9766ee05b1425db397d2cf23afd24c7f6146a69f/common/flatpak-run.c#L2926-L2932) (`move_pages`, `mbind`, `set_mempolicy`, `migrate_pages`)
