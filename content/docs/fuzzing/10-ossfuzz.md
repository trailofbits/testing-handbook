---
title: "OSS-Fuzz"
slug: oss-fuzz
weight: 4
---


# OSS-Fuzz

OSS-Fuzz is an open-source project developed by Google that aims to improve the security and stability of open-source software by providing free distributed infrastructure for continuous fuzz festing. Using a pre-existing framework like OSS-Fuzz has many advantages over manually running harnesses: it streamlines the process and facilitates simpler modifications. Although only select projects are accepted into OSS-Fuzz, because the project’s core is open-source, anyone can host their own instance of OSS-Fuzz and use it for private projects!


This chapter will help project developers understand how to leverage OSS-Fuzz to both fuzz a project on your private instance and delegate the fuzzing computation to Google. Additionally, security researchers will learn how to run a single harness on an existing project, extend a harness, or reproduce an individual crash.


## OSS-Fuzz project components

OSS-Fuzz provides a simple CLI framework for building and starting harnesses or calculating their coverage, which streamlines the process of creating and testing them locally. Additionally, OSS-Fuzz can be used as a service that hosts static web pages generated from fuzzing outputs such as coverage information.


While not all components are open-sourced, we've compiled a list of publicly available OSS-Fuzz tools to showcase the platform's capabilities, with accompanying comments on how you can leverage them for your own work.


* The bug tracker allows for:
   * Checking bugs from a specific project. (Bugs are initially visible only for maintainers, but are later made public.)
   * Creating a new issue and commenting.
   * Reading discussions under public issues.
   * Finding disclosed bugs in all projects, similar to a bug you see in your project, helping you understand the issue. (You can search for any phrase in all OSS-Fuzz public issues.)
* The build status system helps you track whether everything is functioning correctly and, if not, for how long issues have been occurring, specifically:
   * The build statuses of all included projects.
   * The date of the last successful build.
* Fuzz Introspector displays the coverage of a project enrolled in OSS-Fuzz, including coverage data and hit frequency, allowing you to understand the performance of the fuzzer and identify any blockers.
   * To learn more about this tool, read this case study with explanations and examples.

## CLI: Running a single harness

You don't need to host the whole OSS-Fuzz platform to use it. Instead, OSS-Fuzz provides a handy helper script to easily access its features. For instance, you can run a single fuzzing harness to identify potential vulnerabilities in a given project or run a harness with input that previously caused it to crash. You can also use the helper script to test new fuzzing harnesses or run old ones under different configurations; this could encompass usage scenarios like a crashing input or a different compiler.


First, clone the main oss-fuzz repository and use the infra/helper.py script as follows to see possible actions of the helper script:


```sh
$ git clone https://github.com/google/oss-fuzz
$ cd oss-fuzz
$ python3 infra/helper.py --help
```


To run a harness, follow these steps:
* First, execute the helper script with the build_image argument, supplying your project's name: build_image --pull <project-name>
* Next, run the helper script again with the build_fuzzers command followed by your selected sanitizers and project name: build_fuzzers --sanitizer=<sanitizers-list> <project-name>. For AddressSanitizer with LeakSanitizer, use --sanitizer=address. Sanitizers’ support for languages other than C or C++ may be limited; for example, Rust supports only AddressSanitizer with libfuzzer as an engine.
* Finally, to run the fuzzer, use the run_fuzzer command followed by your project name and harness name, and optionally any fuzzer arguments: run_fuzzer <project-name> <harness-name> [<fuzzer-args>]


The helper script should automatically run any missed steps if you skip one.


The build_fuzzers command builds the fuzz targets into the /build/out/<project-name>/ directory, which contains the llvm-symbolizer, harnesses, dictionaries, corpus, etc. Crash files will be saved there as well.


```
PRO TIP: When working on a new harness, refrain from copying code from the source code or pulling it manually. Instead, look at the Dockerfile (or other harnesses) to understand how the code is copied to the Docker image. There's a strong possibility that the existing project's configuration includes a code-pulling process, ensuring that the most recent version is already available when you use helper scripts.
```
## Coverage analysis

OSS-Fuzz can also generate a webpage code coverage report for your project.


* First, install gsutil. You can skip gcloud initialization (gcloud init). 
* Then build harnesses with Coverage Sanitizer (python3 infra/helper.py --sanitizer=coverage <project-name>). 
* Finally, run Coverage Analysis and host the page. You may request use of the local corpus (--no-corpus-download). The following command will generate and host the report locally, displaying a local web address in the console.
   * python3 infra/helper.py coverage <project-name>


Refer to the official OSS-Fuzz documentation for detailed instructions.

### Example

To show how to use the OSS-Fuzz scripts to fuzz a project, let's explore a simple project enrolled into OSS-Fuzz – irssi. We assume here that you can run containers with the docker command.


Let's start by cloning the OSS-Fuzz repository:


```sh
git clone https://github.com/google/oss-fuzz
cd oss-fuzz
```


Then we can build and run the fuzzing harness by invoking the following commands in the main oss-fuzz directory:


```sh
python3 infra/helper.py build_image irssi
python3 infra/helper.py build_fuzzers --sanitizer=address irssi
python3 infra/helper.py run_fuzzer irssi irssi-fuzz
```


We should see the following output that comes from the libFuzzer framework, which is used within the irssi fuzzing harnesses:


```sh
$ python3 infra/helper.py run_fuzzer irssi irssi-fuzz
INFO:__main__:Running: docker run --rm --privileged --shm-size=2g --platform linux/amd64 -i -e FUZZING_ENGINE=libfuzzer -e SANITIZER=address -e RUN_FUZZER_MODE=interactive -e HELPER=True -v /private/tmp/oss-fuzz/build/out/irssi:/out -t gcr.io/oss-fuzz-base/base-runner run_fuzzer irssi-fuzz.
Using seed corpus: irssi-fuzz_seed_corpus.zip
/out/irssi-fuzz -rss_limit_mb=2560 -timeout=25 /tmp/irssi-fuzz_corpus -max_len=2048 < /dev/null
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 1531341664
INFO: Loaded 1 modules   (95687 inline 8-bit counters): 95687 [0x1096c80, 0x10ae247),
INFO: Loaded 1 PC tables (95687 PCs): 95687 [0x10ae248,0x1223eb8),
INFO:      719 files found in /tmp/irssi-fuzz_corpus
INFO: seed corpus: files: 719 min: 1b max: 170106b total: 367969b rss: 48Mb
#720        INITED cov: 409 ft: 1738 corp: 640/163Kb exec/s: 0 rss: 62Mb
#762        REDUCE cov: 409 ft: 1738 corp: 640/163Kb lim: 2048 exec/s: 0 rss: 63Mb L: 236/2048 MS: 2 ShuffleBytes-EraseBytes-
#818        REDUCE cov: 409 ft: 1738 corp: 640/163Kb lim: 2048 exec/s: 0 rss: 63Mb L: 188/2048 MS: 1 EraseBytes-
#880        NEW    cov: 409 ft: 1739 corp: 641/164Kb lim: 2048 exec/s: 0 rss: 63Mb L: 116/2048 MS: 2 CrossOver-InsertRepeatedBytes-
#912        REDUCE cov: 409 ft: 1739 corp: 641/163Kb lim: 2048 exec/s: 0 rss: 63Mb L: 146/2048 MS: 2 EraseBytes-CopyPart-
#933        NEW    cov: 412 ft: 1742 corp: 642/164Kb lim: 2048 exec/s: 0 rss: 63Mb L: 13/2048 MS: 1 ChangeBit-
(...)
```

## Docker images in OSS-Fuzz

Harnesses are built and executed in Docker containers with the build directory mounted as a volume. All projects share a runner image. Each project is built in its own Docker image, which should be indirectly based on this base image.


```
PRO TIP: A base image uses a specific Ubuntu version. Also, a specific compiler version is inherited from the base_clang image, but maintainers can install anything in the project's Docker image (this may require an approval if the project is going to be enrolled).
```


Fuzz targets are built in a Docker image dedicated to the project. (As a project maintainer, you should prepare a Dockerfile for installing dependencies and pulling source code). 


{{< hint info >}}
Your Docker image should be based on one provided by OSS-Fuzz, and it’s best to use compilers provided by that image, if possible.
{{< /hint >}}

Below is a sequence of images. Each subsequent bullet builds on the previous one:
* base_image: a specific version of Ubuntu
* base_clang: compiles clang, which is used to compile most of the projects; based on base_image
* base_builder: some build dependencies, based on base_clang
   * For languages other than C and C++, you can find images like base_builder_go. For a full list, check the /oss-fuzz/infra/base-images/ directory.
* Your project Docker image to build fuzzing targets (based on base_builder/base_builder_*): you must create this one.


The following images are used separately to run harnesses, common for all projects:
* base_runner (based on base_clang)
* base_runner_debug (with debug tools, based on base_runner)


## Using your project with OSS-Fuzz

If you’re working on an open-source project, we recommend enrolling it in OSS-Fuzz so it is fuzzed continuously on Google's infrastructure for free. Be aware that acceptance into OSS-Fuzz is ultimately at the discretion of the OSS-Fuzz team. OSS-Fuzz gives each new project proposal a criticality score (see this example) and uses this value to determine if a project should be accepted. However, you can still add projects to your own copy of OSS-Fuzz; fuzzing only your projects may help to streamline the process. Below is an explanation of how to fuzz a simple project with OSS-Fuzz.
* Generally, you have to create three files: project.yaml (general information about the project), Dockerfile (image with all build dependencies), and build.sh (building harnesses).
* Before starting to work on your own files, it’s best to look at files of existing projects enrolled in oss-fuzz.
* It is recommended to keep source code for harnesses outside of the oss-fuzz project. Some projects create a separate repo for fuzzing, like cURL.
* The entire current process is described on the oss-fuzz getting started page, so check that page for details.


## How ToB integrated a project into OSS-Fuzz

Check out this pull request that adds the cbor2 project, an encoding and decoding library for the CBOR serialization format, to OSS-Fuzz. Specifically, pay attention to:
1. The initial message in the PR that briefly introduces the cbor2 library, and its dependents.
2. The Criticality score given to the project
3. The actual OSS-Fuzz project configuration and harnesses implementation. Yes, it’s that simple!


 Refer to our Continuously Fuzzing Python C Extensions blog post for more information.


See our FAQ for more guidance on using fuzzers, including OSS-Fuzz!

