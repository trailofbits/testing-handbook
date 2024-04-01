---
title: "Installation and first steps"
slug: installation
summary: "This section explains the process of installing Semgrep and how to start using it."
weight: 1
---

# Installation and first steps

## Initial setup

For detailed installation instructions, please refer to the official
[Installing and running Semgrep locally](https://semgrep.dev/docs/getting-started/#installing-and-running-semgrep-locally)
documentation.

### Installing Semgrep

Depending on your operating system and preferences, there are several ways to install Semgrep.
{{< tabs "installing-semgrep" >}}

{{< tab "Python package installer" >}} To install Semgrep with pip, run the following command:

```sh
python3 -m pip install semgrep
```

{{< /tab >}}
{{< tab "Homebrew" >}} If you use macOS or Linux, you can install Semgrep with Homebrew. To install Semgrep with Homebrew,
run the following command:

```sh
brew install semgrep
```

{{< /tab >}}
{{< tab "Semgrep as Docker container" >}} If you prefer to use Semgrep in a Docker container, you can use the official Semgrep
Docker image.
You can find the latest Semgrep Docker image on the [Docker Hub](https://hub.docker.com/r/returntocorp/semgrep) page.
{{< /tab >}}
{{< /tabs >}}

### Keeping Semgrep up to date

Semgrep is a security tool that is constantly being improved with new features and bug fixes. It is important to stay updated
with the latest releases to take advantage of these improvements and ensure your security testing is as effective as possible.

#### Checking for updates

Semgrep will notify you if a new version is available when you run it. If an update is available,
you will see a message like this:

```shell
$ semgrep -c auto
# (...)
A new version of Semgrep is available. See https://semgrep.dev/docs/upgrading
```

You can also check for updates manually by visiting the
[Semgrep Releases](https://github.com/returntocorp/semgrep/releases) page.

#### Updating Semgrep

Depending on how you installed it, there are several ways to update Semgrep. Refer to the official
[Updating Semgrep](https://semgrep.dev/docs/upgrading/) documentation for more detailed information.

{{< tabs "updating-semgrep" >}}
{{< tab "Python Package Installer" >}} Updating with Python Package Installer (pip):

```shell
python3 -m pip install --upgrade semgrep
```

{{< /tab >}}

{{< tab "Homebrew" >}} Updating with Homebrew:

```shell
brew upgrade semgrep
```

{{< /tab >}}

{{< tab "Semgrep as Docker container" >}}
If you use Semgrep in a Docker container, you can update it by rebuilding the container with the latest Semgrep image.
You can find the latest Semgrep Docker image on the [Docker Hub](https://hub.docker.com/r/returntocorp/semgrep) page.
{{< /tab >}}
{{< /tabs >}}

## Running Semgrep

### Before you start

{{< hint danger >}}

#### Caution #1: Privacy

Auto mode (via the `--config auto` argument) requires submitting metrics online, which means that some metadata about
the scanned source code will be sent to Semgrep's servers. This is not an issue for open-source projects,
but should be considered when using Semgrep against proprietary code (see: [Semgrep Privacy Policy](https://semgrep.dev/docs/metrics/)).
You can disable metrics running Semgrep using its `--metrics=off` argument.

{{< /hint >}}

#### Caution #2: Ignored files

The default Semgrep configuration skips the `/tests`, `/test`, and `/vendors` folders. If you want to scan them, use the
`.semgrepignore` file to customize which ones to skip. For more information on how to use `.semgrepignore`,
refer to the [Semgrep documentation on ignoring files and folders](https://semgrep.dev/docs/ignoring-files-folders-code/).

Here's a quick overview of common syntax for including or excluding single files and using wildcards:

- To ignore a specific file or directory, add its path to the `.semgrepignore` file:

  ```sh
  path/to/ignore/file.ext
  path_to_ignore/
  ```

- To ignore all files with a specific extension, use a wildcard `*`:

  ```sh
  *.ext
  ```

### Preliminary run with “auto” configuration

Use the following command in your repository to automatically detect and use relevant built-in rulesets based on
an identified programming language or filename:

```sh
semgrep --config auto
```

### Tailoring rulesets for optimal security testing

When it comes to security testing, specificity and focus are key. While Semgrep's "auto" configuration offers a
convenient starting point by automatically applying general rules based on your code, it might not always yield the most
accurate results. To minimize false positives and decrease noise in your findings, selecting only the rulesets relevant
to your codebase is essential.

By customizing your rulesets, you will streamline the testing process and save time on issues that don't pertain to your
code.
Though the "auto" configuration serves as a useful initial step in security testing, it is crucial to fine-tune your
rulesets for a more precise and efficient analysis that caters to your specific needs.

1. **Exploring Semgrep registry**: Visit the [Semgrep Registry](https://semgrep.dev/explore) to identify rulesets that
meet your needs. Semgrep Registry provides a wide range of rulesets, enabling you to find the ones that align with your
organization's requirements and coding standards.
2. **Disabling metrics collection**: If you prefer not to send anonymous usage metrics while using Semgrep, you can
disable them using either of these methods:

   - Set the [SEMGREP_SEND_METRICS](https://semgrep.dev/docs/cli-reference/#:~:text=SEMGREP_SEND_METRICS) environment variable.
    This can be done in your shell configuration file, or by exporting the variable in your current shell session:

      ```sh
      export SEMGREP_SEND_METRICS=off
      ```

      Once the environment variable is set, Semgrep will not send anonymous usage metrics during execution.

   - Use the `alias` command:

     ```sh
     alias semgrep="semgrep --metrics=off"
     ```

     This command creates an alias for the Semgrep command with the `--metrics=off` option. Whenever you use Semgrep,
     the aliased command will be executed, ensuring that metrics are not sent. Add the alias command to your shell
     configuration file to create a _persistent_ alias that remains available across terminal sessions
     (the specific file depends on the shell you are using).

     {{< hint danger >}}Be cautious with the `alias` command approach, as aliases work only in interactive shell sessions.
     If you run Semgrep from a script, it will still send metrics. We recommend using the environment variable method
     as the primary option for disabling metrics collection.{{< /hint>}}

3. **Using customized rulesets**: To perform a scan in the current directory and its subdirectories
using the selected ruleset, run the following command:
   - For a ruleset existing in the Semgrep Registry:

     ```sh
     # Runs the trailofbits ruleset with Semgrep
     semgrep --config="p/trailofbits"
     ```

   - For the ruleset in a directory (e.g., not in the Semgrep registry):

     ```sh
     # Runs Semgrep rules from the /home/semgrep-rules directory
     semgrep -f /home/semgrep-rules
     ```

    {{< hint info >}}You can use the `-c`, `-f`, or `--config` flags interchangeably, as they all serve the same purpose
    of specifying a ruleset to use during the scan.{{</hint>}}

   - To run multiple predefined rules simultaneously, provide multiple `--config` (or its short forms `-c` or `-f`) arguments:

     ```sh
     semgrep --config="p/trailofbits" --config="p/r2c-security-audit"
     ```

   - Use the ephemeral rules, e.g. `semgrep -e 'exec(...)' --lang=py ./`, to supply a rule inline.

4. **Overview of output formats**: Semgrep supports multiple output formats to help you conveniently analyze results
according to your preferences and tooling.

   a. Available formats:
      You can choose from various output formats for Semgrep scan results, including Emacs, JSON, GitLab SAST,
      GitLab Secrets, JUnit XML, SARIF, and Vim formats. Run `semgrep scan --help` to see all available output formats.

   b. Using output formats with external tools:
     - **SARIF format**: Use the SARIF format with the Visual Studio Code and the
       [SARIF Explorer](https://marketplace.visualstudio.com/items?itemName=trailofbits.sarif-explorer) extension.
       This makes it easy to review the analysis results and drill down into specific issues to understand their
       impact and severity. Example usage of the `p/default` ruleset with the SARIF output file:

       ```sh
       semgrep -c p/default --sarif --output scan_results.sarif
       ```

     - **VIM format**: Use the VIM format to have all the information about a finding in a single line, making it
      convenient for users of the Vim text editor. Example usage of the `p/default` ruleset with the VIM output file:

       ```sh
       semgrep -c p/default --vim --output scan_results.vim
       ```

   c. Filtering and limiting results:
     - Use the `--severity [INFO|WARNING|ERROR]` flag to report findings only from rules that match
       the specified severity (`INFO`/`WARNING`/`ERROR`).
     - There is currently no obvious flag to limit results based on specific rule metadata (e.g., impact).
       See the [Feature request: CLI support for filtering by rule metadata](https://github.com/returntocorp/semgrep/issues/6752)
       GitHub issue for a possible workaround.

   d. Data flow tracing:

      Use the `--dataflow-traces` flag to understand how non-local values contribute to a finding. This option generates
      detailed output showing the data flow between variables, function calls, and other code elements that lead to the
      reported issue.

      For example, in the following scenarios, data flow tracing can be beneficial:
      - Suppose Semgrep identifies a potential SQL injection vulnerability. In that case, data flow tracing can help you
        track how user input is passed through various functions and eventually used in an unsafe SQL query. This will
        enable you to pinpoint where proper input sanitization should be implemented.
      - Suppose Semgrep detects a possible path traversal vulnerability. In that case, data flow tracing can provide you
        with the sequence of code elements that led to the vulnerability, such as the source of the unsanitized input,
        the function that processes it, and the file I/O operation that exposes the vulnerability. Analyzing this data
        allows you to identify the root cause more effectively and apply the appropriate fix.

      This flag is currently compatible with taint mode, tracing the flow of tainted data from its _source_ to its _sink_.

      Consider the [following example](https://semgrep.dev/s/X4AK), which demonstrates standard Semgrep output:

      ```shell
      $ semgrep -f taint_mode_test.yml taint_mode.py
       # (...)
       Found unsanitized flow

                 3┆ return output(data)
       # (...)
      ```

      By incorporating the `--dataflow-traces` option, you can obtain a more detailed analysis:

      ```shell
      $ semgrep --dataflow-traces -f taint_mode_test.yml taint_mode.py
      # (...)
      Found unsanitized flow

                3┆ return output(data)
                ⋮┆----------------------------------------

                Taint comes from:
                 taint_mode.py
                  2┆ data = get_user_input()

                Taint flows through these intermediate variables:
                  2┆ data = get_user_input()

                This is how taint reaches the sink:
                 taint_mode.py
                  3┆ return output(data)
      # (...)
      ```

      Also, you can use the `--json` (JSON output) for further processing:

      ```sh
      $ semgrep --json --dataflow-traces -f rule.yml test3.py
      Scanning 1 file.
      # (...)
      {
      # (...)
      "path": "test3.py",
      "start": { "col": 5, "line": 8, "offset": 146 } }}],
      "taint_sink": ["CliLoc", [ {"end": {"col": 29,"line": 10,"offset": 226 },
      "path": "test3.py","start": { "col": 12, "line": 10, "offset": 209 }
      },
      "html_output(data)"]],
      "taint_source": ["CliLoc", [{ "end": {"col": 28,"line": 8,"offset": 169},
      "path": "test3.py", "start": { "col": 12, "line": 8, "offset": 153 }},
      "get_user_input()"]]
      },
      "engine_kind": "OSS",
      "lines": "    return html_output(data)",
      "message": "Found dangerous HTML output",
      "severity": "WARNING"
      # (...)
      },
      # (...)
      ```

    e. Output verbosity and debugging:
      - Use the `--verbose` flag to show detailed information about which rules are running, which files are skipped,
        etc.
      - Use the `--debug` flag to display the same information as when using the `--verbose` flag, with additional
     debugging information.

### Managing third-party Semgrep rules

By default, you can access various rules in the [Semgrep Explore](https://semgrep.dev/explore) website and apply them
automatically in Semgrep. For instance, to use CWE Top 25 rules, follow this command:

```sh
semgrep --config "p/cwe-top-25"
```

Supplementing the default rules provided by Semgrep Explore with external rules created by individual security researchers
and others can enhance your testing capabilities. However, numerous rulesets are stored in the repositories the
authors manage and may not be included in the official Semgrep repositories. To effectively manage these rules,
consider using [semgrep-rules-manager](https://github.com/iosifache/semgrep-rules-manager/).
The purpose of the semgrep-rules-manager is to collect high-quality Semgrep rules from third-party sources.

To begin using the semgrep-rules-manager and download all custom Semgrep rules supported by it, follow these steps:

```sh
# Install semgrep-rules-manager via pip (see https://github.com/iosifache/semgrep-rules-manager#installation for more info)
$ pip install semgrep-rules-manager

# Create a new directory for downloaded Semgrep rules
$ mkdir -p $HOME/custom-semgrep-rules

# Use semgrep-rules-manager to download custom rulestes
$ semgrep-rules-manager --dir $HOME/custom-semgrep-rules download
✅ 7 sources were successfully downloaded

# Show downloaded Semgrep rules
$ ls $HOME/custom-semgrep-rules
0xdea  community  dgryski  elttam  gitlab  kondukto  trailofbits

# Run downloaded rules in the current directory
$ semgrep -f $HOME/custom-semgrep-rules
```

Please note that semgrep-rules-manager may also download rulesets that are already included in Semgrep Explore, such as
`community`, `trailofbits`, `dgryski`, or `gitlab`.

### Additional tips for running Semgrep

- Implement the [autocomplete feature](https://semgrep.dev/docs/cli-reference/#autocomplete)
  to use the `TAB` key to expedite your workflow while working with the command line.
- If you get the error `No file descriptors available` when running Semgrep on a large codebase, this indicates
an excess of open files. To solve this problem, use the UNIX `ulimit` command to increase the allowed number of file descriptors.

  To increase the allowed number of file descriptors using the UNIX `ulimit` command, you can use the following commands:

  ```sh
  # Check the current limit of file descriptors:
  $ ulimit -n
  256
  # To increase the limit, use the following command,
  # replacing NEW_LIMIT with the desired number of file descriptors:
  $ ulimit -n NEW_LIMIT # e.g. ulimit -n 4096
  ```

  Remember that this change will apply only to the current terminal session.
