---
title: "Advanced usage"
slug: advanced
summary: "This section describes how to create and test custom CodeQL queries and query packs."
weight: 10
---

# Advanced usage

## Creating new query packs

CodeQL queries are written in a declarative, object-oriented language called
QL (for Query Language). QL uses a Java-like syntax to define functions and
classes, and an SQL-like syntax for defining queries.

CodeQL queries are organized into query packs. The root of the query pack is
identified by a `qlpack.yml` file containing metadata about the queries defined
by the pack. To define a custom query, we first need to create a corresponding
query pack.

To create a new query pack, run `codeql pack init <scope>/<name>`. (Here,
_scope_ is the name of the GitHub account or GitHub organization that the
queries will be published to, and _name_ is some name which identifies the query
pack within this namespace.) This will create a new directory _name_ in the
current directory with a minimal `qlpack.yml` file:

```yaml
---
library: false
warnOnImplicitThis: false
name: <scope>/<name>
version: 0.0.1
```

CodeQL uses semantic versioning, and the version will be initialized to 0.0.1
by default.

If you are using the CodeQL VSCode extension to write and run queries, [it can
initialize the query pack and create the `qlpack.yml` file automatically](#running-custom-queries-using-the-vscode-extension).

Most probably you will write at least a few packs. Setup the following directory structure for the easiest development:
```
.
├── CODEOWNERS
├── LICENSE
├── README.md
├── cpp
│   ├── lib
│   │   ├── qlpack.yml
│   │   └── scope
│   │       └── crypto
│   │           └── someLibrary.qll
│   ├── src
│   │   ├── qlpack.yml
│   │   ├── codeql-suites
│   │   │   ├── scope-cpp-code-scanning.qls
│   │   │   └── scope-cpp-security.qls
│   │   ├── crypto
│   │   │   ├── SomeCryptoAnalysis.ql
│   │   ├── security
│   │   │   ├── AppSecAnalysis
│   │   │   │   ├── AppSecAnalysis.c
│   │   │   │   ├── AppSecAnalysis.qhelp
│   │   │   │   └── AppSecAnalysis.ql
│   │   ├── docs
│   │   │   ├── crypto
│   │   │   │   ├── SomeCryptoAnalysis.md
│   │   │   └── security
│   │   │       └── AppSecAnalysis.md
│   └── test
│       ├── qlpack.yml
│       ├── include
│       │   ├── libc
│       │   │   ├── stubs.h
│       ├── library-tests
│       │   └── crypto
│       │       ├── someLibrary
│       │       │   ├── someLibrary.expected
│       │       │   ├── someLibrary.ql
│       │       │   └── someLibrary.c
│       └── query-tests
│           ├── crypto
│           │   ├── SomeCryptoAnalysis
│           │   │   ├── SomeCryptoAnalysis.expected
│           │   │   ├── SomeCryptoAnalysis.qlref
│           │   │   └── SomeCryptoAnalysis.c
│           └── security
│               └── AppSecAnalysis
│                   ├── AppSecAnalysis.c
│                   ├── AppSecAnalysis.expected
│                   └── AppSecAnalysis.qlref
├── go
│   ├── src
...
```

We divide query packs per-language, but also per-type (security, cryptographic, etc.). This follows GitHub's convention.


### Adding dependencies

To be able to define a custom query we need to import the CodeQL standard
library for the language we are analyzing. Thus, we need to add the standard
library as a dependency in the `qlpack.yml` file. This can either be done by
editing the Yaml-file directly, or by using the `codeql pack add` command.

{{< tabs "adding-query-pack-deps" >}}

{{< tab "C/C++" >}}

To add (the latest version of) the CodeQL standard library for C and C++ as a
dependency, run the following command in the root directory of the query pack:

```sh
codeql pack add codeql/cpp-all
```

This will add the following two lines to `qlpack.yml`:

```yaml
dependencies:
  codeql/cpp-all: ^X.Y.Z
```

{{< /tab >}}

{{< tab "Go" >}}

To add (the latest version of) the CodeQL standard library for Golang as a
dependency, run the following command in the root directory of the query pack:

```sh
codeql pack add codeql/go-all
```

This will add the following two lines to `qlpack.yml`:

```yaml
dependencies:
  codeql/go-all: ^X.Y.Z
```

{{< /tab >}}

{{< tab "Java/Kotlin" >}}

To add (the latest version of) the CodeQL standard library for Java and Kotlin
as a dependency, run the following command in the root directory of the query
pack:

```sh
codeql pack add codeql/java-all
```

This will add the following two lines to `qlpack.yml`:

```yaml
dependencies:
  codeql/java-all: ^X.Y.Z
```

{{< /tab >}}

{{< tab "JavaScript/TypeScript" >}}

To add (the latest version of) the CodeQL standard library for JavaScript and
TypeScript as a dependency, run the following command in the root directory of
the query pack:

```sh
codeql pack add codeql/javascript-all
```

This will add the following two lines to `qlpack.yml`:

```yaml
dependencies:
  codeql/javascript-all: ^X.Y.Z
```

{{< /tab >}}

{{< tab "Python" >}}

To add (the latest version of) the CodeQL standard library for Python as a
dependency, run the following command in the root directory of the query pack:

```sh
codeql pack add codeql/python-all
```

This will add the following two lines to `qlpack.yml`:

```yaml
dependencies:
  codeql/python-all: ^X.Y.Z
```

{{< /tab >}}

{{< tab "Swift" >}}

To add (the latest version of) the CodeQL standard library for Swift as a
dependency, run the following command in the root directory of the query pack:

```sh
codeql pack add codeql/swift-all
```

This will add the following two lines to `qlpack.yml`:

```yaml
dependencies:
  codeql/swift-all: ^X.Y.Z
```

{{< /tab >}}

{{< tab "Ruby" >}}

To add (the latest version of) the CodeQL standard library for Ruby as a
dependency, run the following command in the root directory of the query pack:

```sh
codeql pack add codeql/ruby-all
```

This will add the following two lines to `qlpack.yml`:

```yaml
dependencies:
  codeql/ruby-all: ^X.Y.Z
```

{{< /tab >}}

{{< tab "C#" >}}

To add (the latest version of) the CodeQL standard library for C# as a
dependency, run the following command in the root directory of the query pack:

```sh
codeql pack add codeql/csharp-all
```

This will add the following two lines to `qlpack.yml`:

```yaml
dependencies:
  codeql/csharp-all: ^X.Y.Z
```

{{< /tab >}}

{{< /tabs >}}

(If you are manually updating the dependencies in `qlpack.yml` and are unsure
of the version you want, you can use `"*"` which always resolves to the latest
version.)

## Writing custom queries

{{< hint info >}}
To write custom CodeQL queries, you need access to the standard libraries and queries. We recommend using the starter workspace.

1. Clone the [vscode-codeql-starter](https://github.com/github/vscode-codeql-starter.git) repository to your computer:
`git clone --recursive https://github.com/github/vscode-codeql-starter.git`
2. In VSCode, click **File** -> **Open Workspace from File** and open the
`vscode-codeql-starter.code-workspace` file from the `vscode-codeql-starter` repository

{{< /hint >}}

QL is a declarative language and CodeQL queries are expressed using an SQL-like
syntax on the following form:

```mysql
from Type x where P(x) select f(x)
```

Here `P(x)` is some predicate containing the variable `x`, and `f(x)` is an
expression containing `x`. This query is most easily understood as a
[set comprehension](https://en.wikipedia.org/wiki/set-builder_notation), where
we select all instances `f(x)` where `x` is a member of the base set `Type`,
and `P(x)` is true.

To give a concrete example, consider the following query, which selects all
expressions passed as the first argument in a call to the `memcpy` function.

```mysql
import cpp

from
  FunctionCall call
where
  call.getTarget().getName() = "memcpy"
select
  call.getLocation(), call.getArgument(0)
```

Here, the base set is the set of all function calls, which corresponds to the
type [`FunctionCall`](https://codeql.github.com/codeql-standard-libraries/cpp/semmle/code/cpp/exprs/Call.qll/type.Call$FunctionCall.html)
defined by the CodeQL standard library for C and C++, and the predicate `P(x)`
is given by:

```mysql
x.getTarget().getName() = "memcpy"
```

The expression `f(x)` is given by `x.getArgument(0)`.

### CodeQL classes, methods, and functions

The CodeQL standard libraries define a large number of types and functions that
can be used to construct queries, and it is also possible to define new types
and functions to create abstractions on top of the standard libraries.

For example, say that we want to create a new type which represents all calls to
the `memcpy` function as above. This is done by defining a new CodeQL _class_
as follows:

```mysql
import cpp

class MemcpyCall extends FunctionCall {
  MemcpyCall() {
    this.getTarget().getName() = "memcpy"
  }

  Expr getDestination() {
    result = this.getArgument(0)
  }

  Expr getSource() {
    result = this.getArgument(1)
  }

  Expr getSize() {
    result = this.getArgument(2)
  }
}

from
  MemcpyCall call
select
  call.getLocation(), call.getDestination()
```

New types must always _extend_ (i.e., subclass) an existing CodeQL type. In this
case, we extend `FunctionCall`, which corresponds to defining a subset of the
set of all function calls in the code base. The method `MemcpyCall()` is known
as the _characteristic predicate_ of the class and contains the condition that
needs to be true for a function call to be considered a `MemcpyCall`. (Note that
this is also a set comprehension where we create the subset of all expressions
in the set `FunctionCall` which satisfy the characteristic predicate.)

The class additionally defines a number of methods to access the individual
arguments passed to `memcpy`. Methods and functions in CodeQL are multivalued,
which means that they can take more than one value. For this reason, it is
generally easier to think of methods and functions as syntactic sugar for the
corresponding relation between the inputs and outputs (given by the `result`
variable). If multiple outputs satisfy this relation for a given set of inputs,
the method or function will be multivalued.

If a CodeQL method or function is known to be multivalued, this is often
indicated by naming the function `getAnX` instead of `getX`. (An example is the
multivalued method `getAnArgument` on the [`FunctionCall`](https://codeql.github.com/codeql-standard-libraries/cpp/semmle/code/cpp/exprs/Call.qll/type.Call$FunctionCall.html)
type which returns any of the arguments passed to the function.)

### Universal and existential quantification

CodeQL supports bounded quantification using the keywords `exists` and `forall`.
For example, to define a predicate `isNeverCalled(fun)` which is true if the
function `fun` is never called, you can use the existential quantifier `exists`
as follows:

```mysql
predicate isNeverCalled(Function fun) {
  not exists(FunctionCall call |
    call.getTarget() = fun
  )
}
```

Informally, this expresses that there is no function call `call` which calls
`fun` (i.e., where `call.getTarget()` is equal to `fun`).

### Recursion and transitive closures

CodeQL provides built-in support for recursive predicates. As an example, to
express the fact that a [basic block](https://en.wikipedia.org/wiki/Basic_block)
`end` is reachable from another basic block `start`, we could define a predicate
`isReachableFrom(start, end)` which captures this as follows:

```mysql
predicate isReachableFrom(BasicBlock start, BasicBlock end) {
  start = end or isReachableFrom(start.getASuccessor(), end)
}
```

This basically says that the basic block `end` is reachable from `start` if
either `end` is equal to `start` or `end` is reachable from a direct successor
of `start`.

CodeQL also provides language support for transitive closures. Informally, the
_transitive closure_ of a predicate `P` is the result of applying `P` repeatedly
one or more times. Sometimes it is also useful to consider the reflexive,
transitive closure of `P`, which would correspond to applying the predicate
`P` zero or more times. CodeQL supports both of these constructions natively.
The `+` operator is used to denote the application of a predicate _one_ or
more times, and `*` is used to denote the application of a predicate _zero_ or
more times. As an example, we could rewrite the `isReachableFrom(start, end)`
predicate defined above using transitive closures as follows:

```mysql
predicate isReachableFrom(BasicBlock start, BasicBlock end) {
  end = start.getASuccessor*()
}
```

This expresses the fact that the basic block `end` is reachable from `start`
if `end` can be obtained by applying the `getASuccessor()` method zero or more
times to `start`. Hopefully, it is clear that this definition is equivalent to
the recursive definition given above. (To exclude the case where `end` is equal
to `start`, we would replace `*` with `+` in the example above.)

### Adding query metadata

The query metadata is defined in an initial comment using the following syntax:

```mysql
/**
 * @name <A short name>
 * @id <scope>/<query-name>
 * @description <A longer description>
 * @kind <The query type>
 * @tags <A list of tags>
 * @problem.severity <The severity of the issue>
 * @precision <The precision of the query>
 */
```

It is used to populate the SARIF output from the CodeQL CLI, and by tools like
VSCode and GitHub code scanning to display code scanning results to the user.
Adding query metadata is not strictly required if you're only running queries
using `codeql query run`, but it is good practice to always include the
following metadata fields with every query.

- **name**: This should be a short string identifying the underlying issue
  identified by the query. It is used to describe the issue in SARIF output
  and GitHub code scanning results.
- **id**: This should be a unique identifier for the query. It may contain
  lowercase letters, numbers, `/`, and `-`.
- **description**: A longer description of the issue (typically a few sentences)
  identified by the query.
- **kind**: The query type. This can be either `problem` for normal queries, or
  `path-problem` for [path queries](https://codeql.github.com/docs/writing-codeql-queries/creating-path-queries/).
- **tags**: A space separated list of lowercase tags. These can be used to define
  query suites based on tags. See the [official documentation](https://docs.github.com/en/code-security/codeql-cli/using-the-advanced-functionality-of-the-codeql-cli/creating-codeql-query-suites#filtering-the-queries-in-a-query-suite)
  for details on how this is done.
- **problem.severity**: This field describes the severity of the identified
  issue and is displayed by tools like VSCode and GitHub code scanning. The
  value should be either `error`, `warning`, or `recommendation`.
- **precision**: This field indicates the overall probability of false positives
  generated by the query and can be used to filter code scanning results. It
  should be one of `low`, `medium`, `high`, or `very-high`.

{{< hint warning >}}
Note that the query kind also restricts the query output format if you want to
run your query using either `codeql database analyze` or as part of a [GitHub
code scanning]({{< relref "20-ci#code-scanning-with-custom-queries" >}})
workflow.

For `problem` queries, the output from the select statement must be given by a
`Location`, giving the location of the identified issue, followed by a `string`,
describing the identified issue. For `path-problem` queries, the output
must be given by a `DataFlow::Node` representing the sink, followed by two
`DataFlow::PathNode` instances representing the source and sink, followed by a
`string` describing the underlying issue.
{{< /hint >}}

### The CodeQL standard libraries

The CodeQL standard libraries are language specific and there are significant
differences between the different library APIs. We recommend anyone who wants
to develop custom queries to refer to the API documentation for the relevant
language.

- [The CodeQL standard library for Go](https://codeql.github.com/codeql-standard-libraries/go/)
- [The CodeQL standard library for C#](https://codeql.github.com/codeql-standard-libraries/csharp/)
- [The CodeQL standard library for Ruby](https://codeql.github.com/codeql-standard-libraries/ruby/)
- [The CodeQL standard library for Swift](https://codeql.github.com/codeql-standard-libraries/swift/)
- [The CodeQL standard library for Python](https://codeql.github.com/codeql-standard-libraries/python/)
- [The CodeQL standard library for C and C++](https://codeql.github.com/codeql-standard-libraries/cpp/)
- [The CodeQL standard library for Java and Kotlin](https://codeql.github.com/codeql-standard-libraries/java/)
- [The CodeQL standard library for JavaScript and TypeScript](https://codeql.github.com/codeql-standard-libraries/javascript/)

## Running custom queries

To run the query above against an existing database, save the query to the file
`MemcpyCall.ql` under the root directory of the query pack (i.e., the directory
containing the `qlpack.yml` file). We can now run the query using the `codeql query run`
command as follows:

```sh
codeql query run --database codeql.db -- path/to/MemcpyCall.ql
```

Running the query will list the location (i.e., the absolute path, line number
and column number) of all calls to `memcpy` in the codebase, together with the
first argument passed to the function.

## Unit testing custom queries

CodeQL provides a simple testing framework to ensure that custom queries behave
as expected. CodeQL tests must be organized under a separate test pack defined
by its own `qlpack.yml` file.

```yml
name: <scope>/<name-test>
version: 0.0.1
dependencies:
  <codeql-query-pack-to-test>: "*"
extractor: <language-of-code-to-test>
```

Create a sub-directory under the root directory of the test pack for each
query you would like to test. It is good practice to reuse the query name
when naming the sub-directory. That is, if we want to create a unit test for
the `MemcpyCall.ql` query, we name the test directory `MemcpyCall`. The test
directory should contain the following three files:

- `test.c`: A source file containing the code pattern identified by the query
- `MemcpyCall.qlref`: A [text file](https://docs.github.com/en/code-security/codeql-cli/using-the-advanced-functionality-of-the-codeql-cli/query-reference-files)
  containing the location of the query to test
- `MemcpyCall.expected`: A text file containing the expected output from
  running the query against the source file

The source file must build cleanly without any external dependencies. To test
the query, run the following command:

```sh
codeql test run -- path/to/test/pack/root/directory
```

This will run all tests in the test pack. To test a single query you can specify
the corresponding test directory when running `codeql run test`.

If the `MemcpyCall.expected` file is missing or does not match the actual
output generated by the query, an error is raised and an `MemcpyCall.actual`
file is created with the actual output from CodeQL. This allows you to
investigate any unexpected behavior, but also provides a convenient way of
generating the initial `MemcpyCall.expected` file: Run the test without a
`MemcpyCall.expected` file to generate `MemcpyCall.actual`. Review the output
to ensure that it is correct and if it is, rename `MemcpyCall.actual` to
`MemcpyCall.expected`.

For more information about testing CodeQL queries, see the
[official documentation](https://docs.github.com/en/code-security/codeql-cli/using-the-advanced-functionality-of-the-codeql-cli/testing-custom-queries).

## Testing custom queries in CI

### GitHub Actions

The following workflow can be used to test custom CodeQL queries in GitHub Actions:

```yml
name: Test CodeQL queries

on: [push, pull_request]

jobs:
  codeql-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - id: init
        uses: github/codeql-action/init@v3
      - uses: actions/cache@v4
        with:
          path: ~/.codeql
          key: ${{ runner.os }}-${{ runner.arch }}-${{ steps.init.outputs.codeql-version }}
      - name: Run tests
        run: |
          ${{ steps.init.outputs.codeql-path }} test run ./path/to/query/tests/
```

This workflow also speeds up subsequent runs by caching query extraction and
compilation, and pack dependency installation.

## Editor support for CodeQL

The CodeQL CLI includes a server for the language-server protocol (LSP)
which can be used to provide code navigation and diagnostics for editors with
LSP support. There is also a [Tree-sitter grammar for CodeQL](https://github.com/tree-sitter/tree-sitter-ql)
in the official Tree-sitter repository, which can be used to provide syntax
highlighting in editors like Helix. Additionally, there are plugins for
[VSCode](https://marketplace.visualstudio.com/items?itemName=GitHub.vscode-codeql)
and [Neovim](https://github.com/pwntester/codeql.nvim), which provide LSP
support, syntax highlighting, and allow you to run queries and navigate
issues directly from the editor.

### Running custom queries using the VSCode extension

The VSCode CodeQL extension provides a convenient way of running queries, as
well as visualizing and navigating the results of custom queries. The extension
also allows you to run single queries against an existing database via the
"CodeQL: Quick Query" command.

If you are writing a new query you can use the VSCode extension to automatically
configure a `qlpack.yml` file based on the selected programming language and
create a skeleton query via the "Create one to get started" button found under
the Queries tab.

{{< figure src="/generate-codeql-query.png" width="500"
alt="Create a skeleton query using the Queries tab in the VSCode extension" >}}

### Debugging custom queries using the VSCode extension

The VSCode extension also allows you to display the abstract syntax tree (AST) for
each AST node in the database. This feature can be very useful when debugging
custom queries.

To display the AST view for a node, you need to first set the CodeQL database to
use and then add the database source code to the workspace. This is done as
follows:

1. **Set the CodeQL Database:** Navigate to the CodeQL extension view and set the
   CodeQL database using either "Choose Database from Folder" or "Choose Database
   from Archive" as applicable.
2. **Add Source code to Workspace:** Right-click the database name in the "Databases"
   view and choose "Add Database Source to Workspace". This will add a copy of each
   source file in the database to the file picker under `[<codeql-database-name> source archive]`.

   {{< hint warning >}}
   Note that the extension sometimes forgets the database chosen in the previous
   step when the source code is added to the workspace in this way. If this happens,
   simply reset the database as above.
   {{< /hint >}}
3. **View AST:** To view the AST of an AST node in the database, navigate to the
   corresponding source file _inside the database source directory_. Then use
   the "CodeQL: View AST" command to show the AST for the file. Each node is
   displayed together with its corresponding CodeQL type, and you can navigate
   the tree by clicking the individual nodes.

{{< figure src="/view-codeql-ast.png" alt="An example of the CodeQL AST in VSCode" >}}
