---
title: "Advanced usage"
slug: advanced
summary: "This section explores the advanced usage of Semgrep, including how to create new rules."
weight: 10
---

# Advanced usage

## Ignoring (parts of) code in your project with Semgrep

Semgrep identifies programming languages based on their file extensions rather than content analysis.
Use the `--scan-unknown-extensions` flag and the `--lang` flag to specify the language you want Semgrep
to use when scanning files with non-standard extensions. For example:

```sh
semgrep --config /path/to/your/config --lang python --scan-unknown-extensions /path/to/your/file.xyz
```

In this example, Semgrep will scan the `/path/to/your/file.xyz` file as a Python file,
even though the `.xyz` extension is not a standard Python file extension.

See also the [Allow user to specify file extensions for languages #3090](https://github.com/semgrep/semgrep/issues/3090)
GitHub issue to work around restrictions if you want to use Semgrep against your specific language, even if the file
extension is not standard.

### Files/directories

- By default, Semgrep follows the default
[.semgrepignore](https://github.com/semgrep/semgrep/blob/develop/cli/src/semgrep/templates/.semgrepignore) file.
- If present, Semgrep will look at the repository's `.gitignore` file.
- In case of a conflict between the two files, the `.semgrepignore` file takes precedence. This means that if the
  `.gitignore` file includes a file and the `.semgrepignore` file excludes it, Semgrep will not analyze the file.

Before starting a scan, it is recommended that you review the files and directories in your project directory.
Note that certain paths may be excluded by default. If you want to change the default exclusion behavior,
such as including third-party libraries or unit tests in the scan, you can create a custom `.semgrepignore` file.

### Excluding code sections

To prevent Semgrep from flagging incorrect code patterns, insert a comment in your code immediately before or on the line
preceding the pattern match (e.g., `// nosemgrep: rule-id`). It is crucial to have a space between `//` and `nosemgrep`.

As a best practice, remember to:

- Exclude only particular findings in your comments rather than disabling all rules with a generic `// nosemgrep` comment.
- Explain why you disabled a rule or justify your risk acceptance decision.
- If you encounter a false positive and want to ignore a Semgrep rule, provide feedback to either the Semgrep development
team or your internal development team responsible for the specific rule. This will help improve the accuracy
of the rule and reduce the chances of future false positives.

For more information on how to use `nosemgrep` to ignore code blocks for a particular rule, refer to the
[Semgrep documentation on ignoring code](https://semgrep.dev/docs/ignoring-files-folders-code/#ignoring-code-through-nosemgrep).

## Writing custom rules

While Semgrep offers a library of pre-built rules, creating custom rules can significantly enhance your security testing
by tailoring it to your specific codebase and requirements. However, creating effective Semgrep rules can be challenging
without proper guidance and understanding. This section will give you the essential knowledge and skills to create
high-quality Semgrep rules. You will learn about the rule language's syntax and how to develop effective patterns,
handle edge cases, and create powerful custom Semgrep rules. This will aid in detecting potential security vulnerabilities
early on, ultimately improving your testing process.

### Example custom rule

As a starting point for creating a custom rule, use the following schema to create the `custom_rule.yaml` file.

```yaml {linenos=inline}
rules:
  - id: rule-id
    languages: [go]
    message: Some message
    severity: ERROR # INFO / WARNING / ERROR
    pattern: test(...)
```

### Running custom rules

- To run the above-mentioned rule as a single file, use the following command:

```shell
semgrep --config custom_rule.yaml
```

- To run a set of rules in a directory:

```shell
semgrep --config path/
```

### ABCs of writing custom rules

To start writing custom Semgrep rules, it is crucial to understand a few key concepts and tools:

1. **Familiarize yourself with Semgrep syntax**: Begin by exploring the official [Learn Semgrep Syntax](https://semgrep.dev/learn)
page, which provides a comprehensive guide on the fundamentals of Semgrep rule writing.
1. **Refer to language-specific pattern examples**: Consult the [Semgrep Pattern Examples by Language](https://semgrep.dev/embed/cheatsheet)
for examples tailored to specific programming languages.
1. **Use the Semgrep Playground**: The [Semgrep Playground](https://semgrep.dev/playground/new) is a convenient online tool
for writing and testing rules. However, it is essential to consider the following points when using the Playground:
{{< hint danger >}}**Be cautious of privacy concerns**: The Semgrep Playground allows users to experiment with code
      without downloading or installing software on their local machine. While this platform is helpful for testing
      and debugging rules, it may expose sensitive information such as passwords, API keys, or other secrets contained
      in the code you submit for scanning.
      Always use a local development environment with proper security and privacy controls for sensitive code.{{< /hint >}}
    - **Employ the `simple mode`**: The Semgrep Playground's simple mode makes it easy to combine rule patterns.
    - **Use the `Share` button**: Share your rule and test code with others using the Share button.
    - **Add tests to your test code**: Incorporate [tests](https://semgrep.dev/docs/writing-rules/testing-rules/)
      (e.g., `# ruleid: <id>`) into your test code to evaluate your rule's effectiveness while working in the Semgrep
      Playground (see [example](https://semgrep.dev/s/ezxE)).
    - **Note the limitations with comments**: Be aware that the Semgrep Playground does not retain comments when sharing
      a link or "forking" a rule (Ctrl+S). Refer to this [GitHub issue](https://github.com/semgrep/semgrep/issues/7120)
       for more information.

### Building blocks

#### Ellipses (`...`)

{{< hint info >}}**Purpose**: The ellipsis (`...`) is used to match zero or more arguments, statements, parameters,
and so on, allowing for greater flexibility in pattern matching.
{{< /hint >}}

Here is an example rule for Python:

```yaml {linenos=inline}
rules:
  - id: rule-id
    languages: [Python]
    message: Some message
    severity: INFO
    pattern: requests.get(..., verify=False, ...)
```

Here, the ellipsis before and after the `verify=False` argument allows the pattern to match
any number of arguments before and after the `verify` parameter. This ensures that the pattern
can match function calls with various argument combinations, as long as the `verify=False` argument is present.

This pattern matches the following code snippets:

```python {linenos=inline, hl_lines=[1,3,6]}
requests.get(verify=False, url=URL)
requests.post(verify=False, url=URL)
requests.get(URL, verify=False, timeout=3)
requests.head()
requests.get(URL)
requests.get(URL, verify=False)
```

In the second example, the ellipsis is used to create a pattern that matches an `if` statement
followed by an unnecessary `else` block after a `return` statement within the `if` block.

Below is the `unnecessary-if-else-pattern` rule for Python:

```yaml {linenos=inline}
rules:
  - id: unnecessary-if-else-pattern
    languages: [Python]
    message: Unnecessary else after return $X
    severity: INFO
    pattern: |
      if ...:
        return ...
      else:
        ...
```

Now, let's break down the pattern components:

1. `if ...:`: This part of the pattern matches any `if` statement, regardless of the condition being tested.
The ellipsis within the `if` statement is a wildcard that matches any expression or code structure used as the condition.
This flexibility ensures that the pattern can detect a wide range of `if` statements with various conditions.
2. `return ...`: Within the matched `if` block, the `return` statement is followed by an ellipsis. This wildcard matches
any expression or value being returned. This allows the pattern to detect `return` statements with different values or
expressions, such as `return True`, `return False`, `return x`, or `return calculate_result()`.
3. `...` within the `else` block: The ellipsis in the `else` block is a wildcard that matches any number of statements.

This pattern matches the following code snippet:

```py {linenos=inline}
if a > b:
  return True
else:
  print("a is not greater than b")
```

By including the ellipsis (`...`) in your Semgrep rules, you can create more flexible and comprehensive patterns that account
for variations in code structure.

#### Metavariables

{{< hint info >}}**Purpose**: Metavariables are used to match and track values across a specific code scope.
They are denoted by a dollar sign followed by a capitalized letters (e.g., `$X`, `$Y`, `$COND`).{{< /hint >}}

Here is an example pattern in Golang:

```yaml
pattern: $X.($TYPE)
```

The metavariable `$X` matches:

```go {linenos=inline, hl_lines=[1,2]}
msg, ok := m.(*MsgDonate) // $X = m
p := val.(types.Pool) // $X = val
x := val
msg, ok = m
```

Metavariables can also be interpolated into the output message of a Semgrep rule.
For instance, consider the following rule:

```yaml {linenos=inline}
rules:
  - id: metavariable-example-rule
    patterns:
      - pattern: func $X(...) { ... }
    message: Found $X function
    languages: [golang]
    severity: WARNING
```

For the following code:

```go {linenos=inline}
func test123(input string) {
    fmt.Println("test")
}
```

This returns the `Found test123 function` message in the Semgrep output, as follows:

```shell
$ semgrep -f rule.yml
# (...)
     metavariable-example-rule
        Found test123 function

          1┆ func test123(input string) {
          2┆     fmt.Println("test")
          3┆ }
```

Metavariables help create more dynamic and versatile Semgrep rules by capturing values that can be used for further
pattern matching or validation.

##### Leveraging metavariables

Metavariables can be used in a variety of ways to enhance Semgrep rules, making
them more dynamic and adaptable when analyzing code. Some common use cases include:

1. **Matching variable names**: Metavariables can be used to match variable names in the code,
allowing the rule to be flexible and applicable to various situations. For example:

    ```yaml
    pattern: $X := $Y
    ```

    This pattern would match assignments like `a := b` or `result := calculation()`.

2. **Capturing function calls**: Metavariables can be employed to capture function calls and their arguments.
    This can be useful for detecting potentially unsafe or deprecated functions. For example:

    ```yaml
    pattern: $FUNC($ARG)
    ```

    This pattern would match function calls like `dangerousFunc(input)` or `deprecatedFunc(arg1, arg2)`.

3. **Matching control structures**: Metavariables can help identify specific control structures,
such as loops or conditionals, with a particular focus on the expressions used within these structures. For example:

    ```yaml
    pattern: for $INDEX := $INIT; $COND; $UPDATE { ... }
    ```

    This pattern would match for-loops like `for i := 0; i < 10; i++ { ... }`.

4. **Comparing code patterns**: Metavariables can be used to compare different parts of the code to ensure consistency
or prevent potential bugs. For example, you can detect cases where the same assignment is
made in both branches of an `if-else` statement:

    ```yaml
    pattern: if $COND { $X = $Y } else { $X = $Y }
    ```

    This pattern would match code like:

    ```go {linenos=inline}
    if someCondition {
        x = y
    } else {
        x = y
    }
    ```

5. **Identifying patterns across multiple lines**: Metavariables can be employed to match and track values
across multiple lines of code, making it possible to detect patterns that span several statements. For example:

    ```yaml
    pattern: |
      $VAR1 := $EXPR1
      $VAR2 := $VAR1
    ```

    This pattern would match code like the following:

    ```go {linenos=inline}
    a := b + c
    d := a
    ```

In conclusion, metavariables offer a powerful way to create dynamic and adaptable Semgrep rules. They help capture
and track values across code scopes, enabling the identification of complex patterns and providing informative output
messages for developers and security professionals.

#### Nested metavariables

{{< hint info >}}**Purpose**: Nested metavariables allow you to match a pattern with a metavariable that also contains
another metavariable meeting certain conditions.{{< /hint >}}

Here is an example rule:

```yaml {linenos=inline}
rules:
  - id: metavariable-pattern-nest
    languages: [python]
    message: substraction in foo(bar(...))
    patterns:
      - pattern: foo($X, ...)
      # First metavariable-pattern
      - metavariable-pattern:
          metavariable: $X
          patterns:
            - pattern: bar($Y)
            # Nested metavariable pattern
            - metavariable-pattern:
                metavariable: $Y
                patterns:
                  - pattern: ... - ...
    severity: WARNING
```

This rule matches the following Python code:

```python {linenos=inline}
foo(bar(1-2))
foo(bar(bar(1-2)))
```

Nested metavariables allow for more complex and precise pattern matching in Semgrep rules by allowing you to define
relationships between multiple metavariables.

#### Using `metavariable-pattern` for polyglot file scanning

{{< hint info >}}**Purpose**: To match patterns across different languages within a single file
(e.g., JavaScript embedded in HTML).{{< /hint >}}

Example: Find all instances of JavaScript's [eval](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval)
function used in an HTML file ([example](https://semgrep.dev/s/W9by)).

```yaml {linenos=inline}
rules:
  - id: metavariable-pattern-nest
    languages: [html]
    message: eval in JS
    patterns:
      - pattern: <script ...>$Y</script>
      - metavariable-pattern:
          metavariable: $Y
          language: javascript
          patterns:
            - pattern: eval(...)
    severity: WARNING
```

This rule matches the following HTML code:

```html {linenos=inline}
<script>
    console.log('test123');
    eval(1+1);
</script>
```

Using `metavariable-pattern` allows for cross-language pattern matching in polyglot files, enabling you to identify
specific code patterns within mixed-language files.

#### Using `metavariable-pattern` + `pattern-either`

{{< hint info >}}**Purpose**: To specify multiple alternative patterns
that can match a metavariable.{{< /hint >}}

Example: Flag instances where a variable declaration uses one of several specific types
([example](https://semgrep.dev/s/J0zk)
/
[trailofbits.go.string-to-int-signedness-cast.string-to-int-signedness-cast](https://semgrep.dev/playground/r/trailofbits.go.string-to-int-signedness-cast.string-to-int-signedness-cast?editorMode=advanced)
rule).

```yaml {linenos=inline}
rules:
  - id: metavariable-pattern-multiple-or
    languages: [go]
    message: xyz
    patterns:
      - pattern: var $A $TYPE = ...
      - metavariable-pattern:
          metavariable: $TYPE
          pattern-either:
            - pattern: uint8
            - pattern: uint16
            - pattern: uint32
            - pattern: int8
            - pattern: int16
            - pattern: int32
    severity: WARNING
```

This rule matches the following Go code:

```go {linenos=inline, hl_lines=["1-6"]}
var a uint8 = 255
var b uint16 = 65535
var c uint32 = 4294967295
var d int8 = -128
var e int16 = -32768
var f int32 = -2147483648
var g string = "xyz"
```

Combining `metavariable-pattern` with `pattern-either` allows you to create Semgrep rules that match a `metavariable` if
it meets any of the specified conditions.

#### Metavariable-pattern + patterns

{{< hint info >}}**Purpose**: Use `metavariable-pattern` and `patterns` to flag instances where a metavariable `$X`
meets _all_ conditions (`patterns`) ([example](https://semgrep.dev/s/BJqv) / [lxml-in-pandas rule](https://semgrep.dev/playground/r/trailofbits.python.lxml-in-pandas.lxml-in-pandas?editorMode=advanced))
{{< /hint >}}

Here is an example rule:

```yaml {linenos=inline}
rules:
  - id: metavariable-pattern-and-patterns
    languages:
      - go
    message: xyz1
    patterns:
      - pattern: var $A $TYPE = $Z
      - metavariable-pattern:
          metavariable: $Z
          patterns:
            - pattern-not: |
                  -128
            - pattern-not: |
                  -32768
    severity: WARNING
```

This rule matches the following Go code:

```go {linenos=inline, hl_lines=[1,3]}
var b uint16 = 65535
var d int8 = -128
var c uint32 = 4294967295
var e int16 = -32768
```

#### Constant propagation

Constant propagation in Semgrep refers to the process of matching instances where a `metavariable` holds a specific value
or relation.

##### Matching instances where a metavariable holds a specific value

{{< hint info >}}**Purpose**: To match instances where a metavariable holds a specific value or relation, use
the `metavariable-comparison` key.{{< /hint >}}

Example: Match cases where the variable `$X` is greater than `1337` ([example](https://semgrep.dev/s/LqeL)).

```yaml {linenos=inline}
rules:
  - id: metavariable-comparison
    languages: [python]
    message: $X is higher than 1337
    patterns:
      - pattern: function($X)
      - metavariable-comparison: # Match when $X > 1337
          metavariable: $X
          comparison: $X > 1337
    severity: WARNING
```

This rule matches the following Python code:

```python {linenos=inline, hl_lines=["2-3"]}
n = 1339
function(n) # Match (n > 1337)
function(1338) # Match (constant > 1337)
function(123)
```

##### Comparing specific metavariables

{{< hint info >}}**Purpose**: Compare specific metavariables.{{< /hint >}}

Example: Match functions where the first argument is lower than the second one ([example](https://semgrep.dev/s/dYnd)).

```yaml {linenos=inline}
rules:
  - id: metavariable-comparison-rule
    patterns:
      - pattern: f($A, $B)
      - metavariable-comparison:
          comparison: int($A) < int($B)
          metavariable: $A
    message: $A < $B
    languages: [python]
    severity: WARNING
```

This rule matches the following Python code:

```python {linenos=inline,hl_lines=["1-2"]}
f(1,2)
f(2,3)
f(4,3)
f(12312,1)
```

#### Deep expression operator

{{< hint info >}}**Purpose**: To match deeply nested expressions in the code.{{< /hint >}}
Deep expression operator is useful when you want to identify specific patterns that are buried within complex structures
like conditional statements, loops, or function calls. Using the deep expression operator, you can create rules that
target specific code patterns regardless of how deep they are in the code structure.

The deep expression operator is represented by `<... ...>`. It acts as a wildcard that matches any code structure between
the opening and closing ellipses. By using the deep expression operator, you can create Semgrep rules that match patterns
in any level of nesting.

**Example**: Matching a function call nested within an `if` statement ([example](https://semgrep.dev/s/2Qv8)).

Suppose you want to match any instance of a specific function call (e.g., `user.is_admin()`) within an `if` statement,
regardless of how deeply nested it is.

```yaml {linenos=inline}
rules:
- id: deep-expression-example
  pattern: |
      if <... user.is_admin() ...>:
        print(...)
  message: if statement with is_admin() check
  languages: [python]
  severity: WARNING
```

This rule matches the following Python code:

```python {linenos=inline}
if user.authenticated() and user.is_admin() and user.has_group(gid):
    print("hello")
```

#### Understanding `pattern-inside` and `pattern-not-inside`

##### Using `pattern-inside`

By using `pattern-inside`, you can create rules that match patterns only when they appear
**within** a certain code construct, like a function, or class definition, a loop, or a conditional block.

Here's an example of how you might use `pattern-inside` to detect cases where a sensitive function is called within a loop:

```yaml {linenos=inline}
rules:
- id: sensitive_function_in_loop
  languages:
    - python
  message: "Sensitive function called inside a loop"
  severity: WARNING
  patterns:
    - pattern-inside: |
        for ... in ...:
            ...
    - pattern: |
        sensitive_function(...)
```

In this example, the `pattern-inside` operator is used to match any `for` loop in Python, and the second
pattern matches calls to `sensitive_function()`. The rule will trigger only if both patterns are matched,
meaning that the `sensitive_function` is called **inside** a loop.

Here's an example of Python code that would trigger the `sensitive_function_in_loop` rule:

```python {linenos=inline, hl_lines=[10]}
def sensitive_function(data):
    # Process sensitive data
    pass

def main():
    data_list = ['data1', 'data2', 'data3']

    for data in data_list:
        # Call to sensitive_function is inside a loop
        sensitive_function(data)

def second(data):
    sensitive_function(data)
```

##### Using `pattern-not-inside`

`pattern-not-inside` is the opposite of `pattern-inside` and is used to match a pattern only when it
**does not appear** within a specified context. This operator helps you to exclude certain parts of the
code from your analysis, further refining your rules and reducing false positives.

For instance, you can use `pattern-not-inside` to detect calls to the `print_debug()`
function when they occur outside a `if debug:` block:

```yaml {linenos=inline}
rules:
- id: print_debug_outside_debug_block
  languages:
    - python
  message: "print_debug() should be called inside a 'if debug:' block"
  severity: WARNING
  patterns:
    - pattern-not-inside: |
        if debug:
            ...
    - pattern: |
        print_debug(...)
```

Here is a Python code example demonstrating the use of this rule:

```python {linenos=inline, hl_lines=[11]}
debug = True

def print_debug(msg):
    print("DEBUG:", msg)

def correct_usage():
    if debug:
        print_debug("This is a debug message inside a 'if debug:' block")

def incorrect_usage():
    print_debug("This is a debug message outside a 'if debug:' block")

def main():
    correct_usage()
    incorrect_usage()
```

##### Combining `pattern-inside` and `pattern-not-inside`

In some cases, you might want to create rules that use both `pattern-inside`
and `pattern-not-inside` operators to capture instances where a specific pattern
is found within a particular context but not within another.

**Example**: Detecting `print()` calls in functions but not in `main()`.

Suppose you want to enforce a rule where `print()` calls are allowed only within
the `main()` function and not in any other functions. You can create a rule that
combines `pattern-inside` and `pattern-not-inside` operators to achieve this.

```yaml {linenos=inline}
rules:
- id: print_calls_outside_main
  languages:
    - python
  message: "print() calls should only be inside the main() function"
  severity: WARNING
  patterns:
    - pattern-inside: |
        def $X(...):
            ...
    - pattern-not-inside: |
        def main(...):
            ...
    - pattern: |
        print(...)
```

In this example, the `pattern-inside` operator matches any function definition, while
the `pattern-not-inside` operator ensures that the `main()` function is excluded.
The final pattern matches calls to the `print()` function. The rule will trigger only
when a `print()` call is found inside a function other than `main()`.

Here's an example of Python code that triggers the `print_calls_outside_main` rule:

```python {linenos=inline, hl_lines=[3,11]}
def sample_function():
    # print() call inside a function other than main()
    print("This is a sample function")

def main():
    print("This is the main function")
    sample_function()

def other_function():
    some_function()
    print("XYZ")
```

#### Taint mode

Taint mode is a powerful feature in Semgrep that can track the flow of data from one location to another.
By using taint mode, you can:

1) **Track data flow across multiple variables:** Taint mode enables you to trace how data moves across different variables,
functions, components, and allows you to easily identify insecure flow paths (e.g., situations where a specific sanitizer
is not used).
2) **Find injection vulnerabilities:** Taint mode is particularly useful for identifying injection vulnerabilities such as
SQL injection, command injection, and XSS attacks.
3) **Write simple and resilient Semgrep rules:** Taint mode simplifies the process of writing Semgrep rules that are resilient
to certain code patterns nested in `if` statements, loops, and other structures.

To use taint mode, you need to set the `mode: taint` and specify `pattern-sources`/`pattern-sinks` fields in your custom
Semgrep rule.

See this [example](https://semgrep.dev/s/el3X):

```yaml {linenos=inline}
rules:
  - id: taint-tracking-example1
    mode: taint
    pattern-sources:
      - pattern: getData()
    pattern-sinks:
      - pattern: printToUser(...)
    message: data flows from getData to printToUser
    languages: [python]
    severity: WARNING
```

Optionally, you can use additional fields in your Semgrep rule to further refine your taint analysis:

- `pattern-propagators`: This field allows you to specify functions or methods that propagate tainted data
([example](https://semgrep.dev/s/7Nrv)). You can also refer to
[sanitizers by side-effect](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/#sanitizers-by-side-effect) for
more information.
- `pattern-sanitizers`: This field allows you to specify functions or methods that sanitize tainted data.
For more information, see the [taint mode documentation](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/#propagators).

### Combining patterns

When writing Semgrep rules, you may encounter situations where a single pattern (e.g., `pattern: evil_function(...)`)
isn't sufficient to capture the behavior you want to detect. In these cases, you can use one of the following to combine
patterns:

- `patterns`: This method combines multiple patterns with a logical AND (&&). In other words,
all patterns must match for the rule to trigger. This is useful when you want to detect code snippets that satisfy
multiple conditions simultaneously.
- `pattern-either`: This method combines multiple patterns with a logical OR (||). In other words, if any of the
patterns match, the rule triggers. This is useful when you want to detect code snippets satisfying at least one
specified condition.

    Suppose you want to detect calls to two insecure functions, `insecure_function_1()` and `insecure_function_2()`.
    You can use the `pattern-either` operator to achieve this.

    ```yaml {linenos=inline}
    rules:
    - id: insecure_function_calls
      languages:
        - python
      message: "Call to an insecure function detected"
      severity: WARNING
      patterns:
        - pattern-either:
            - pattern: |
                insecure_function_1(...)
            - pattern: |
                insecure_function_2(...)
    ```

    In this example, the `pattern-either` operator is used to match calls to either `insecure_function_1()`
    or `insecure_function_2()`. The rule will trigger if any of these patterns are matched.

    Here's an example of Python code that triggers the `insecure_function_calls` rule:

    ```yaml {linenos=inline, hl_lines=[9,12]}
    def insecure_function_1():
        print("Insecure function 1 called")

    def insecure_function_2():
        print("Insecure function 2 called")

    def main():
        # Call to insecure_function_1() triggers the rule
        insecure_function_1()

        # Call to insecure_function_2() also triggers the rule
        insecure_function_2()
    ```

- `pattern-regex`: This matches code with a [PCRE](https://www.pcre.org/original/doc/html/pcrepattern.html)-compatible
pattern in multiline mode. In other words, it matches code using a regular expression pattern.

#### Rule syntax diagram

The following diagram will help you understand the relationship between the relevant fields in the rule. While writing
a rule, you can use the advanced mode in the [Semgrep Playground](https://semgrep.dev/playground/new) to test
and refine it. The playground highlights any errors in your rules, providing immediate feedback.

{{< mermaid >}}
flowchart TB

Fields{Rule Fields} ---->|Only one is allowed| Required{Required}
click Fields "https://semgrep.dev/docs/writing-rules/rule-syntax/#optional:~:text=Rule%20syntax-,Rule%20syntax,-TIP"
    Required ==> id
    click id "https://semgrep.dev/docs/writing-rules/rule-syntax/#optional:~:text=Description-,id,-string"
    Required ==> message
    click message "https://semgrep.dev/docs/writing-rules/rule-syntax/#optional:~:text=no%2Dunused%2Dvariable-,message,-string"
    Required ==> severity
    click severity "https://semgrep.dev/docs/writing-rules/rule-syntax/#optional:~:text=Rule%20messages.-,severity,-string"
    Required ==> languages((languages))
    click languages "https://semgrep.dev/docs/writing-rules/rule-syntax/#language-extensions-and-tags"
    Required ===>|Only one is required| Pattern_Fields{Pattern Fields}
    click Pattern_Fields "https://semgrep.dev/docs/writing-rules/rule-syntax/#optional:~:text=pattern*,in%20multiline%20mode"

click Required "https://semgrep.dev/docs/writing-rules/rule-syntax/#required"

Pattern_Fields ==> pattern
click pattern "https://semgrep.dev/docs/writing-rules/rule-syntax/#pattern"
Pattern_Fields ==> pattern-regex[pattern-regex]
click pattern-regex "https://semgrep.dev/docs/writing-rules/rule-syntax/#pattern-regex"
Pattern_Fields ==> pattern-either((pattern-either))
click pattern-either "https://semgrep.dev/docs/writing-rules/rule-syntax/#pattern-either"
Pattern_Fields ==> patterns((patterns))
click patterns "https://semgrep.dev/docs/writing-rules/rule-syntax/#patterns"
pattern-either -.-> pattern-regex
pattern-either -.-> pattern
pattern-either -.-> pattern-inside
click pattern-inside "https://semgrep.dev/docs/writing-rules/rule-syntax/#pattern-inside"
pattern-either <-.-> patterns

patterns -.-> pattern-inside

patterns <-..-> metavariable-pattern{metavariable-pattern}
click metavariable-pattern "https://semgrep.dev/docs/writing-rules/rule-syntax/#metavariable-pattern"
    metavariable-pattern --> metavariable2[metavariable]
    metavariable-pattern -.-> language
    metavariable-pattern -.-> pattern
    metavariable-pattern -.-> pattern-either
    metavariable-pattern -.-> pattern-regex

patterns -.-> metavariable-regex{metavariable-regex}
click metavariable-regex "https://semgrep.dev/docs/writing-rules/rule-syntax/#metavariable-regex"
    metavariable-regex --> metavariable
    metavariable-regex --> regex

patterns -.-> metavariable-comparison{metavariable-comparison}
click metavariable-comparison "https://semgrep.dev/docs/writing-rules/rule-syntax/#metavariable-comparison"
    metavariable-comparison --> metavariable3[metavariable]
    metavariable-comparison --> comparison
    metavariable-comparison -.-> base
    metavariable-comparison -.-> strip

patterns -.-> pattern
patterns -.-> pattern-not
click pattern-not "https://semgrep.dev/docs/writing-rules/rule-syntax/#pattern-not"
patterns -.-> pattern-not-inside
click pattern-not-inside "https://semgrep.dev/docs/writing-rules/rule-syntax/#pattern-not-inside"
patterns -.-> pattern-not-regex
click pattern-not-regex "https://semgrep.dev/docs/writing-rules/rule-syntax/#pattern-not-regex"

Fields -.-> Optional{Optional}

Optional -.-> options(options)
Optional -.-> fix(fix)
Optional -.-> metadata(metadata)
Optional -.-> paths(paths)

click Optional "https://semgrep.dev/docs/writing-rules/rule-syntax/#optional"
click options "https://semgrep.dev/docs/writing-rules/rule-syntax/#options"
click fix "https://semgrep.dev/docs/writing-rules/rule-syntax/#fix"
click metadata "https://semgrep.dev/docs/writing-rules/rule-syntax/#metadata"
click paths "https://semgrep.dev/docs/writing-rules/rule-syntax/#paths"
{{< /mermaid >}}

**Example #1**:
Looking at the chart, you can see that the `pattern-either` and `pattern-not` fields are not directly connected.
However, you can combine them using the `patterns` field, which performs a logical AND operation on all the patterns included.

**Example #2**:
For instance, if you want to use `pattern-either` to combine multiple patterns with a logical OR and exclude a specific
pattern using `pattern-not`, you can do so by including both of them under the same `patterns` field.
The resulting combination of patterns will match only code that satisfies all of the patterns included in
the `pattern-either` field, except for the pattern specified in `pattern-not`.
See the example [`exclude-when-using-secure-option`](https://semgrep.dev/s/vgob) rule.

### Generic pattern matching

It is possible to match generic patterns in unsupported languages/contexts.
Use the `generic` language for configuration files, XML, etc., and combine it with the specific extension
through the `paths` - `include` fields to reduce false positives.

For example, see the [`nsc-allows-plaintext-traffic`
rule](https://semgrep.dev/playground/r/java.android.best-practice.network-security-config.nsc-allows-plaintext-traffic?editorMode=advanced),
which scans the Android manifest XML file for potential misconfiguration:

```yaml {linenos=inline}
rules:
  - id: nsc-allows-plaintext-traffic
    languages: [generic]
    patterns:
      - pattern: |
          <base-config ... cleartextTrafficPermitted="true" ... >
      - pattern-not-inside: |
          <!-- ... -->
      - pattern-not-inside: >
          <network-security-config ... InsecureBaseConfiguration ... > ... ...
          ... ... ... ... ... ... ... ... </network-security-config>
    severity: INFO
    paths:
      include:
        - "*.xml"
```

### Metadata

Metadata fields are a feature in Semgrep that allow you to attach additional information to your rules.
By including metadata fields in your rules, you can give developers more context and guidance on addressing potential issues.
This information can include details such as the rule's severity level, recommended fixes, or the author's contact information.
By including metadata, you can make your rules more informative and actionable for developers who encounter them.
This can help them prioritize and fix issues more efficiently, ultimately improving the overall security of your codebase.

In addition to providing context and guidance to developers, there are several other reasons why an organization
might want to use Semgrep metadata:

1. **Standardization.** Using metadata fields consistently across all of your organization's Semgrep rules ensures that
developers see the same types of information and recommendations no matter which rules they encounter.
This can help standardize the security review process and simplify prioritizing and addressing issues.
   - Example: [By including fields required by the security category in the Semgrep Registry](https://semgrep.dev/docs/contributing/contributing-to-semgrep-rules-repository/#including-fields-required-by-security-category),
   developers will prioritize findings with high `confidence` and high `impact` metadata.
2. **Collaboration.** Including author information in your Semgrep rules can make it easier for other organization members
to collaborate on security issues.
    - Example: Suppose someone has a question or needs more information about a particular rule. In that case, they can
    contact the `author` directly for clarification.
3. **Compliance.** Suppose your organization needs to comply with specific security regulations or standards.
In this case, you could include a `compliance` metadata field in your Semgrep rules, indicating which regulation or
standard the rule relates to. This helps ensure that your codebase complies with all relevant requirements.

You can create any metadata field, as demonstrated in the [hooray-taint-mode](https://semgrep.dev/playground/s/4K3g) rule.

We recommend including the following metadata fields required by the security category in the Semgrep Registry:

1. `cwe`: A [Common Weakness Enumeration](https://cwe.mitre.org/index.html) identifier that classifies the security issue.
2. `confidence`: An assessment of the rule's accuracy, represented as high, medium, or low.
3. `likelihood`: An estimation of the probability that the detected issue will be exploited, represented as high,
medium, or low.
4. `impact`: A measure of the potential damage caused by exploiting the detected issue, represented as high, medium, or low.
5. `subcategory`: A more specific classification of the rule, falling under one of the following categories:
[vuln, audit, or guardrail](https://semgrep.dev/docs/contributing/contributing-to-semgrep-rules-repository/#subcategory).

By including these metadata fields, you provide valuable context and help users better understand the security
implications of the issues detected by your rule.

### Various tips

#### Matching an array with a non-string element

This Semgrep rule aims to detect JavaScript or TypeScript arrays that contain at least one non-string element.
See this [array-with-a-non-string-element example](https://semgrep.dev/s/BJnb).

```yaml {linenos=inline}
rules:
  - id: array-with-a-non-string-element
    languages: [js]
    message: array with element that is not a string
    severity: WARNING
    patterns:
      - metavariable-pattern:
          metavariable: $A
          patterns:
            - pattern-not: "..."
      - pattern: [..., $A, ...]
```

#### "Removing" negative pattern from pattern-either

This Semgrep rule aims to detect Python code snippets where a function `a(...)`, `b(...)`, or `c(...)` is called,
but it should not match the case where function `a()` is called with the argument `x`.
See this [pattern-not-with-pattern-either example](https://semgrep.dev/s/5N96)

```yaml {linenos=inline}
rules:
- id: pattern-not-in-pattern-either
  patterns:
    - pattern-either:
       - pattern: a(...)
       - pattern: b(...)
       - pattern: c(...)
    - pattern-not: a(x)
  message: pattern either with one negative pattern
  languages: [python]
  severity: WARNING
```

### Maintaining good quality of Semgrep rules

Before publishing a new rule or updating an existing one, it is crucial to ensure that it meets specific standards and
is effective.
To help with this, we've created a [Development Practices checklist](https://github.com/trailofbits/semgrep-rules/blob/main/CONTRIBUTING.md#development-practices)
in our _Contributing to Trail of Bits Semgrep Rules_ document that you can follow to make sure your custom rule
is ready for publication.

### Help with writing custom rules

{{< hint danger >}}**Warning:** Be careful about asking for external assistance for writing rules or sharing rule output
that may be specific to a sensitive and/or private codebase. Doing so could inadvertently disclose the identity
of the code owner, portions of the code, or particular bugs.{{</hint>}}

When running into issues while working on custom rules, several resources are available to help you.
Two of the most valuable resources are the following:

- The [Semgrep Community Slack](https://go.semgrep.dev/slack) is a great place to ask for help with custom rule
development. The channel is staffed by knowledgeable developers familiar with Semgrep's architecture and syntax.
They are usually quick to respond to questions. They can guide you in structuring your rules and in debugging any issues
that arise. Additionally, the Slack channel is a great place to connect with other developers working on similar
projects, allowing you to learn from others' experiences and share your insights.
- Use [Semgrep GitHub issues](https://github.com/semgrep/semgrep/issues) to report bugs, suggest new features, and
ask for help with specific issues.

## Thoroughly testing Semgrep rules for optimal performance

Creating comprehensive tests for your Semgrep rules is essential to ensure they perform as expected and cover a wide range
of test cases. By thoroughly testing the rules against various code samples, you can confirm that they accurately identify
intended vulnerabilities, potential errors, or coding standard violations. This ultimately leads to more reliable
and effective security and code quality analysis.

### Designing comprehensive test cases

A well-rounded test suite for a custom Semgrep rule should cover multiple aspects of the rule's functionality.

When designing test cases, consider the following:

1. **Create a file containing code samples**: Create a file containing code with the same name as the rule.
For example, if your rule filename is `unsafe-exec.yml`, create a corresponding `unsafe-exec.py` file with sample code.
2. **Incorporate a diverse range of code samples**: Adhere to the following guidelines when adding code samples to the
test file:
    - Include at least one true positive comment (e.g., `// ruleid: id-of-your-rule`).
    - Include at least one true negative comment (e.g., `// ok: id-of-your-rule`).
    - Start with simple, descriptive examples that are easy to understand.
    - Progress to more advanced, complex examples, such as those involving nested structures (e.g., inside an `if` statement)
    or deep expressions.
    - Include edge cases that may challenge the rule's accuracy or efficiency, such as large input values, complex code
    structures, or unusual data types.
    - Test the rule against different language features and constructs, including loops, conditionals, classes, and functions.
    - Intentionally create code samples that should not trigger the rule, and ensure that the rule does not produce
     false positives in these cases.
3. **Ensure all tests pass**: Run the `$ semgrep --test` command to verify that all test cases pass.
4. **Evaluate the rule against real-world code**: Test the rule against actual code from your projects,
open-source repositories, or other codebases to assess its effectiveness in real-life scenarios.

## Testing custom rules in CI

### GitHub Actions

The following workflow can be used to test custom Semgrep rules in GitHub Actions:

```yml
name: Test Semgrep rules

on: [push, pull_request]

jobs:
  semgrep-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v4
        with:
          python-version: "3.11"
          cache: "pip"
      - run: python -m pip install -r requirements.txt
      - run: semgrep --test --test-ignore-todo ./path/to/rules/
```

Make sure to include `semgrep` in your `requirements.txt` (or [`poetry` or `pipenv` equivalents](https://github.com/actions/setup-python/blob/main/docs/advanced-usage.md#caching-packages))
file to speed up workflow runs by caching the dependency. Note, we include
`--test-ignore-todo` here so we do not fail CI runs on [TODO tests](https://semgrep.dev/docs/writing-rules/testing-rules),
which are a valuable form of documentation for future rule improvements.

## Autofix feature

The autofix feature can automatically correct identified vulnerabilities, potential errors, or coding standard violations.

There are many benefits to using the autofix feature:

- Training every developer on all the best practices for large code bases is not feasible. Autofixes can help fill in
the gaps and provide guidance as needed.
- Autofixes maintain developer focus by removing monotonous changes, allowing them to concentrate on more complex tasks.
- Adding autofixes allows developers to be educated and trained on new best practices as they are introduced into the codebase.
- Autofixes can provide on-demand fixes and are much more actionable and educational than simple lint warnings.
- Without making developers aware of a deprecation, they won't know not to use a deprecated component,
  and they won't know what to use instead. Autofixes can help make these transitions smoother.

### Creating a Semgrep rule with the autofix feature

Follow these steps to develop a rule with the autofix feature (see the [ioutil-readdir-deprecated](https://semgrep.dev/s/wPEX)
rule with the autofix feature implemented):

1. Add the `fix` key to a rule, specifying the replacement pattern for the identified vulnerability.

    Here is an example rule with the autofix feature:

    ```yaml {linenos=inline}
    rules:
      - id: ioutil-readdir-deprecated
        languages: [golang]
        message: ioutil.ReadDir is deprecated. Use more efficient os.ReadDir.
        severity: WARNING
        pattern: ioutil.ReadDir($X)
        fix: os.ReadDir($X)
    ```

    For the following Golang code:

    ```go {linenos=inline}
    package main

    import (
      "fmt"
      "io/ioutil"
      "log"
      "os"
    )

    func main() {
        // ruleid: ioutil-readdir-deprecated
      files, err := ioutil.ReadDir(".")
      if err != nil {
        log.Fatal(err)
      }

      for _, file := range files {
        fmt.Println(file.Name())
      }
    }
    ```

2. Run the rule using the standard command to confirm that the rule is detecting the intended issue:

    ```bash
    $ semgrep -f rule.yaml
    # (...)
    Findings:

      readdir.go
        ioutil-readdir-deprecated
            ioutil.ReadDir is deprecated. Use more efficient os.ReadDir.

            ▶▶┆ Autofix ▶ os.ReadDir(".")
            11┆ files, err := ioutil.ReadDir(".")
    # (...)
    ```

3. Run the rule with the `--dryrun` and the `--autofix` options to preview the behavior of the autofix feature on the code
without making any changes to the analyzed code:

    ```bash
    $ semgrep -f rule.yaml --dryrun --autofix
    # (...)
    Findings:

      readdir.go
        ioutil-readdir-deprecated
            ioutil.ReadDir is deprecated. Use more efficient os.ReadDir.

            ▶▶┆ Autofix ▶ os.ReadDir(".")
            11┆ files, err := os.ReadDir(".")
    # (...)
    ```

4. Create a new test file for the autofix by adding the `.fixed` suffix in front of the file extension
(e.g., `readdir.go` -> `readdir.fixed.go`). This file should contain the expected output after the autofix is applied.

    Content of the `readdir.fixed.go` file:

    ```go {linenos=inline}
    package main

    import (
      "fmt"
      "io/ioutil"
      "log"
      "os"
    )

    func main() {
        // ruleid: ioutil-readdir-deprecated
      files, err := os.ReadDir(".")
      if err != nil {
        log.Fatal(err)
      }

      for _, file := range files {
        fmt.Println(file.Name())
      }
    }
    ```

5. Run the test to confirm that the autofix is working as expected:

    ```shell
    $ semgrep --test
    1/1: ✓ All tests passed
    1/1: ✓ All fix tests passed
    ```

6. Now you are ready to apply autofix to the analyzed file with the `--autofix` option.

    ```shell
    $ semgrep -f rule.yaml --autofix
    # (...)
    Findings:

      readdir.go
        ioutil-readdir-deprecated
            ioutil.ReadDir is deprecated. Use more efficient os.ReadDir.

            ▶▶┆ Autofix ▶ os.ReadDir(".")
            11┆ files, err := ioutil.ReadDir(".")
    # (...)
    ```

By following these steps, you can create a custom Semgrep rule with an effective autofix feature that identifies issues
and provides a solution to fix them.

### Regular expression-based autofix

The `fix` field presented above allows you to specify a simple string replacement, while the `fix-regex` field enables
more complex regular expression-based replacements. For more information, refer to the official documentation
on [Autofix with regular expression replacement](https://semgrep.dev/docs/writing-rules/autofix/#autofix-with-regular-expression-replacement).

## Optimizing Semgrep rules

{{< hint info >}}Improve rule performance and minimize false positives through repeatable processes. {{< /hint >}}

Optimizing your Semgrep rules is crucial for maintaining high performance and minimizing false positives.
This section will guide how to create efficient and accurate Semgrep rules.

1. **Analyze time summary**: To include a time summary with the results, use the `--time` flag. This will provide the
   following information:
    - Total time / Config time / Core time
    - Semgrep-core time
      - Total CPU time
      - File parse time
      - Rule parse time
      - Matching time
    - Slowest five analyzed files
    - Slowest five rules to match
2. **Narrow down findings to specific file paths**: Assess whether findings should be limited to specific file paths
 (e.g., Dockerfiles).
    - You can apply particular rules to certain paths using the `paths` keyword. For example, the
      [avoid-apt-get-upgrade](https://semgrep.dev/playground/r/generic.dockerfile.best-practice.avoid-apt-get-upgrade.avoid-apt-get-upgrade)
      rule targets only Dockerfiles:

        ```yaml {linenos=inline,linenostart=17}
          paths:
              include:
                - "*dockerfile*"
                - "*Dockerfile*"
        ```

3. **Use `pattern-inside` and `pattern-not-inside`**: The `pattern-inside` and `pattern-not-inside` clauses allow you to
specify a context in which a pattern should or should not be matched, respectively.

    Consider a scenario where you want to identify calls to `insecure_function()` within a loop,
    followed by a specific statement, such as a call to `log_data()`, but only when the log level is set to `DEBUG`.

    Initially, you can achieve this by using one `pattern` statement:

    ```yaml {linenos=inline}
    rules:
    - id: insecure_function_in_loop_followed_by_debug_log
      languages: [python]
      message: |
        Insecure function called within a loop
        followed by log_data() with log level DEBUG
      severity: WARNING
      pattern: |
        for ... in ...:
            ...
            insecure_function(...)
            ...
            log_data("DEBUG", ...)
    ```

    Here's an example of Python code that triggers the `insecure_function_in_loop_followed_by_debug_log` rule:

    ```python {linenos=inline, hl_lines=["11-17"]}
    def insecure_function():
        print("Insecure function called")

    def log_data(log_level, msg):
        if log_level == "DEBUG":
            print("DEBUG:", msg)

    def main():
        data_list = ['data1', 'data2', 'data3']

    for data in data_list:
        # Call to insecure_function() within a loop,
        # followed by log_data() with log level DEBUG triggers the rule
        insecure_function()
        other_function()
        function1337()
        log_data("DEBUG", "Insecure function called with data: " + data)
    ```

    Running the `insecure_function_in_loop_followed_by_debug_log` rule may not provide the clearest output,
    as it displays the entire `for` loop:

    ```shell
    $ semgrep -f insecure_function_in_loop_followed_by_debug_log.yml
    # (...)
      insecure_function_in_loop_followed_by_debug_log
        Insecure function called within a loop followed by log_data() with log level DEBUG

        11┆ for data in data_list:
        12┆  # Call to insecure_function() within a loop,
        13┆  # followed by log_data() with log level DEBUG triggers the rule
        14┆  insecure_function()
        15┆  other_function()
        16┆  function1337()
        17┆  log_data("DEBUG", "Insecure function called with data: " + data)
    ```

    For such findings, only the calls to `insecure_function()` might be of critical importance. To improve the output,
    you can use the following clauses instead:
    1. `patterns`: This clause combines two sub-patterns with a logical AND operator, meaning all sub-patterns
       must match:

          a. `pattern-inside`: This clause matches any `for` loop in the Python code, establishing the context for
            the subsequent patterns. It sets a condition that must be met for the rule to trigger, acting
            as the first part of a logical AND operation.

          b. `pattern`: This sub-pattern matches calls to any function followed by a call to `log_data("DEBUG", ...)`.
            The rule potentially triggers if this `pattern` and the previous `pattern-inside` match.

          c. `focus-metavariable`: This operator focuses the finding on the line of code matched by `$FUNC`.

          d. `metavariable-pattern`: This sub-pattern restricts `$FUNC` to functions called `insecure_function`.

    Here is a fixed version of the `insecure_function_in_loop_followed_by_debug_log` rule:

    ```yaml {linenos=inline}
    rules:
    - id: insecure_function_in_loop_followed_by_debug_log_fixed
      languages: [python]
      message: |
        Insecure function called within a loop
        followed by log_data() with log level DEBUG
      severity: WARNING
      patterns:
        - pattern-inside: |
            for ... in ...:
                ...
        - pattern: |
            $FUNC(...)
            ...
            log_data("DEBUG", ...)
        - focus-metavariable: $FUNC
        - metavariable-pattern:
            metavariable: $FUNC
            pattern: insecure_function
    ```

    Running the `insecure_function_in_loop_followed_by_debug_log_fixed` Semgrep rule will produce a more concise and
    focused output:

    ```shell
    $ semgrep -f insecure_function_in_loop_followed_by_debug_log_fixed.yml
    # (...)
      insecure_function_in_loop_followed_by_debug_log_fixed
          Insecure function called within a loop followed by log_data() with log level DEBUG

          13┆ insecure_function()
    ```

4. **Minimize the use of ellipses** `...`: While ellipses are a powerful tool for matching a wide range of code snippets,
they can lead to performance issues and false positives when overused. Limit the use of ellipses to situations necessary
for accurate pattern matching.
5. **Determine the necessity of metavariables**: Before using a metavariable in your rule, determine if it is truly necessary.
Metavariables can be useful for capturing and comparing values, but if a metavariable is unnecessary for your rule
to function correctly, consider removing it.

    For example, consider the following Semgrep rule that uses a metavariable `$X`:

    ```yaml {linenos=inline}
    rules:
      - id: unnecessary_metavariable_example
        languages: [python]
        message: The variable is assigned the value 123
        pattern: $X = 123
        severity: WARNING
    ```

    This rule matches any variable assignment with the value `123`. However, the metavariable `$X` might be unnecessary
    if you don't need to capture the variable name. In this case, you can use the `...` operator instead, which matches any
    expression:

    ```yaml {linenos=inline}
    rules:
      - id: without_metavariable_example
        languages: [python]
        message: A variable is assigned the value 123
        pattern: ... = 123
        severity: WARNING
    ```

    By replacing the `$X` metavariable with the `...` operator, you can reduce the complexity and improve the performance
    of your rule without losing the intended functionality. This approach should be used when the metavariable is not essential
    for the rule's purpose or subsequent comparisons or checks.
6. **Test your rules with real-world code**: To ensure the effectiveness of your rules, test them with real-world code samples.
   This lets you identify potential issues and false positives before deploying your rules in a production environment.
