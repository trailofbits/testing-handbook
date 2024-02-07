---
title: "Fuzzing environments"
slug: environments
summary: "TODO"
weight: 4
---

### Fuzzing environments {#fuzzing-environments}

Like any software, the choice of fuzzer will depend on factors such as the operating system, architecture, software versions, and hardware. This section will review factors that influence the choice of the environment used for fuzzing.

**Choice of hardware.** If your fuzzer supports running on multiple cores, choose hardware that has many cores available. [Renting](https://www.hetzner.com/sb?country=us) or purchasing a bare-metal server might be worthwhile if you plan to run campaigns regularly. If not, then [renting](https://www.digitalocean.com/pricing/droplets#cpu-optimized) VMs with many dedicated cores is probably the better choice. 

Keep in mind that achieving many executions per second of your SUT probably outweighs any smart tricks you can apply to your fuzzing setup! Execution speed is crucial.

**Choice of environment.** Ideally, you will fuzz in the same environment that the users of your SUT use. However, to simplify fuzzing it, might be acceptable to fuzz your SUT on Linux even though it usually runs on Windows or macOS. For instance, forking a process on macOS is [slower than on Linux](https://github.com/AFLplusplus/AFLplusplus/blob/358cd1b062e58ce1d5c8efeef4789a5aca7ac5a9/GNUmakefile#L589) (although this may not be an issue, depending on your fuzzer).

A general caveat of many operating systems (including Linux) is that executions per second may not scale linearly with the amount of cores you are using if the SUT interacts with the kernel (e.g., through system calls). If your SUT heavily communicates with the kernel, consider fuzzing on multiple VMs, each of which runs a separate kernel. A rough guideline is that if you fuzz on more than 24 cores, you may want to use multiple VMs. Note that this is relevant only for fuzzers that generally scale well with multiple cores like LibAFL.

As an example, consider a game engine that supports all platforms. In this case, the easiest choice is to fuzz on Linux, because that is the best supported platform overall. However, doing so may miss bugs that affect only Windows. This is a tradeoff you have to make. Starting with the easiest environment and then iteratively fuzzing on other platforms is a good choice.

**A word about Docker.** Docker offers a good way of encapsulating the user space. However, it does not encapsulate the kernel space. Fuzzers like AFL++ configure the system and kernel in a specific way, for example to avoid persisting core dumps to disk. This means that if you use the Docker host for more than fuzzing, or if you run multiple fuzzing campaigns in parallel using multiple Docker containers, you might run into issues: the kernel runtime configuration modified by AFL++ will impact the whole system, including other containers.

The question of whether or not to use Docker also relates to the first point we made earlier in this section, which is the **choice of environment**. If your application typically runs in Docker, you may want to fuzz in a Docker container.

We recommend fuzzing in Linux VMs if possible, because they offer better isolation than containers. Performance-wise, the difference between running in a [privileged](https://docs.docker.com/engine/reference/commandline/run/#privileged) Docker container and a VM is negligible, if native virtualization with the same host and guest architecture is used. However, note that the usage of default configured Docker comes with up to a 50% reduction in performance. Fuzzing in Docker can be slower if the container is not [privileged](https://docs.docker.com/engine/reference/commandline/run/#privileged) or disables [security features](https://mamememo.blogspot.com/2020/05/cpu-intensive-rubypython-code-runs.html).

**Fuzzing in VMs.** If the fuzzing environment should use Linux, you will achieve more robust results by creating separate VMs for each fuzzing project or fuzzing campaign. You may want to experiment with the Trail of Bits' tool [cloudexec](https://github.com/crytic/cloudexec) to distribute tasks across several cloud VMs.

Note that if you are using Docker Desktop on an Apple device, you are actually [launching a VM internally](https://www.docker.com/blog/the-magic-behind-the-scenes-of-docker-desktop/) that is isolated from your macOS system.