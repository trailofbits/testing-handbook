---
title: "Seccomp/BFP"
slug: lang-c-cpp-seccomp
weight: 20
---

## Seccomp

[Sandboxing is hard](https://www.youtube.com/watch?v=gJpaxisyQfY). But if it is needed and seccomp is used, ensure the following is done:

{{< checklist >}}
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
{{< /checklist >}}