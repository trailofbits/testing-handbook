---
title: "Linux Kernel"
slug: lang-c-cpp-linux-kernelmode
weight: 14
---

# Linux kernel

This list includes basic checks for Linux kernel drivers and modules.

{{< checklist >}}

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
  - For example, use of the `%p` format string may leak kernel addresses. The mitigation for this particular issue is to use [`kptr_restrict`](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#kptr-restrict). Developers should use the `%pK` or `%px` format strings.
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

{{< /checklist >}}
