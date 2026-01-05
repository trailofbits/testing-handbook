---
title: "Installation and first steps"
slug: installation
summary: "This section explains the process of installing CodeQL, as well as how to build and analyze a CodeQL database."
weight: 1
---

# Installation and first steps

## Initial setup

For detailed installation instructions, please refer to the official
[documentation](https://docs.github.com/en/code-security/codeql-cli/getting-started-with-the-codeql-cli/setting-up-the-codeql-cli).

### Installing CodeQL

CodeQL can either be installed manually, or if you are on macOS or Linux,
you can alternatively use the package manager Homebrew.

{{< tabs "installing-codeql" >}}

{{< tab "Manual install" >}}
To install the CodeQL CLI manually, navigate to the [CodeQL release page](https://github.com/github/codeql-action/releases)
and download the latest bundle for your architecture.
{{< /tab >}}

{{< tab "Using Homebrew" >}}
On macOS or Linux, you can install CodeQL using Homebrew using the following command:

```sh
brew install --cask codeql
```

{{< /tab >}}

{{< /tabs >}}

In either case, the installed bundle contains the `codeql` binary, query
libraries for supported languages, and pre-compiled versions for all of
the included queries.

### Keeping CodeQL up to date

CodeQL is under active development, and it is important to stay updated with the
latest releases to take advantage of these improvements and ensure your security
testing is as effective as possible.

If you installed CodeQL manually, you need to navigate to the [CodeQL release page](https://github.com/github/codeql-action/releases)
to download new updates. If you used Homebrew to install CodeQL, you can ensure
that your local installation is up to date by running:

```shell
brew upgrade codeql
```

## Building a database

To build a new CodeQL database you typically need to be able to build the
corresponding codebase. Make sure that the codebase is in a clean state (e.g.
by running `make clean`, `go clean`, or similar), and then build the codebase
with the CodeQL CLI as follows:

{{< tabs "building-a-database" >}}

{{< tab "C/C++" >}}

To build a database for a C or C++ project, pass `cpp` as language to the CodeQL
CLI. The build command is specified using the `command` argument.

```shell
codeql database create codeql.db --language=cpp --command='make -j8'
```

If you are using a meta-build system like CMake, you would first execute `cmake`
to generate the build-configuration files and then pass the actual build command
to CodeQL.

If your source files are not in the same tree as where you are building (e.g.
if you are using `cmake` for out-of-source builds), add the `--source-root`
argument when generating the database to correctly set the root of the source
file tree.
{{< /tab >}}

{{< tab "Go" >}}

To build a database for a Golang project, pass `go` as language to the CodeQL
CLI.

```shell
codeql database create codeql.db --language=go
```

If you are using a build script, or more complex build system, you can pass the
build command to the CodeQL using the `--command` argument.

{{< /tab >}}
{{< tab "Java/Kotlin" >}}

To build a database for a Java or Kotlin project, pass `java` as language to the
CodeQL CLI.

```shell
codeql database create codeql.db --language=java
```

If you are using a build script, or more complex build system, you can pass the
build command to the CodeQL using the `--command` argument.

{{< /tab >}}
{{< tab "JavaScript/TypeScript" >}}

To build a database for a JavaScript or TypeScript project, pass `javascript` as
language to the CodeQL CLI.

```shell
codeql database create codeql.db --language=javascript
```

{{< /tab >}}
{{< tab "Python" >}}

To build a database for a Python project, pass `python` as language to the
CodeQL CLI.

```shell
codeql database create codeql.db --language=python
```

{{< /tab >}}
{{< tab "Swift" >}}

To build a database for a Swift project, pass `swift` as language to the CodeQL
CLI.

```shell
codeql database create codeql.db --language=swift
```

If you are using a build script, or more complex build system, you can pass the
build command to the CodeQL using the `--command` argument.

{{< /tab >}}
{{< tab "Ruby" >}}

To build a database for a Ruby project, pass `ruby` as language to the CodeQL CLI.

```shell
codeql database create codeql.db --language=ruby
```

If you are using a build script, or more complex build system, you can pass the
build command to the CodeQL using the `--command` argument.

{{< /tab >}}
{{< tab "C#" >}}

To build a database for a C# project, pass `csharp` as language to the CodeQL CLI.

```shell
codeql database create codeql.db --language=csharp
```

If you are using a build script, or more complex build system, you can pass the
build command to the CodeQL using the `--command` argument.

{{< /tab >}}
{{< /tabs >}}

### Excluding individual files

CodeQL will instrument the build process and successively add information about
each compilation unit to the database. In practice, this means that if the
compiler skips one or more source files (e.g. because the corresponding object
files already exist and are up to date), then the corresponding functions and
types will not be added to the database either. This can be used to reduce the
size of the resulting database. For example, to avoid including third-party
libraries in the database simply build the project once, delete any object files
directly related to the project, and then build the project database using the
CodeQL CLI as above.

However, it is important to remember that ignoring files means that CodeQL
will have only partial knowledge about the corresponding code, and will not be
able to reason about data flow through functions or methods defined in those
files. For this reason, it is often better to include third-party libraries and
filter issues based on the location in the codebase where they occur instead.
This also means that you generally get more comprehensive analysis results if
you vendor third-party libraries than if you rely on dynamic linking at runtime.

### Multi-step builds

It is possible to create a single codeql database from multiple builds.
This may be useful when codebase is built in a few different docker containers or
when there are multiple sub-projects involved.

The process is to use init - trace-command - finalize codeql commands:

```bash
codeql database init \
    --overwrite --source-root=. --language=cpp --begin-tracing \
    -- ${BUILD_CACHE_DATABASE}

codeql database trace-command \
    -- ${BUILD_CACHE_DATABASE} ${CC} -c lib/lib1.c -o lib/lib1.o
codeql database trace-command \
    -- ${BUILD_CACHE_DATABASE} ${CC} -c lib/lib2.c -o lib/lib2.o
codeql database trace-command \
    -- ${BUILD_CACHE_DATABASE} ${CC} main.c lib/lib1.o lib/lib2.o -o main

codeql database finalize -- ${BUILD_CACHE_DATABASE}
```

## Analyzing a database

The CodeQL bundle comes with a set of pre-compiled query packs included. It is
also possible to install third-party query packs using the CodeQL CLI. To see
the list of installed query packs, you can use the following command.

```shell
codeql resolve qlpacks
```

The command `codeql database analyze` runs a set of queries on an existing
database. The output is written to a file and the output format is given as an
argument on the command line. The following command runs the pre-compiled query
pack `codeql/cpp-queries` on a given CodeQL database. The output is written to
the SARIF-file `results.sarif`.

```shell
codeql database analyze codeql.db --format=sarif-latest --output=results.sarif -- codeql/cpp-queries
```

[SARIF](https://github.com/microsoft/sarif-tutorials) is a common output format
used by many static-analysis tools. If you are using VSCode, you can view the SARIF results with the
[VSCode SARIF Explorer extension](https://marketplace.visualstudio.com/items?itemName=trailofbits.sarif-explorer).
Apart from SARIF, CodeQL also supports CSV output.

## Installing new query packs

Apart from the pre-compiled query packs that ship with the CLI bundle, it is
also possible to install third-party query packs using the CodeQL CLI. Published
query packs are identified by their _scope_, _name_, and an optional _version_.
For query packs published to the GitHub container registry, the scope identifies
the organization or account who owns the corresponding repository. The following
command downloads (the latest version of) the `cpp-queries` and `go-queries`
query packs published by Trail of Bits.

```shell
codeql pack download trailofbits/cpp-queries trailofbits/go-queries
```

For more information about our public CodeQL queries and published query packs
we refer to our [trailofbits/codeql-queries](https://github.com/trailofbits/codeql-queries)
repository.
