# Trail of Bits Testing Handbook

![Testing-Handbook-logo][logo]

[logo]:th-logo.jpg

The Trail of Bits Testing Handbook is a resource for developers and security professionals on configuring, optimizing,
and automating many static and dynamic analysis tools we use at Trail of Bits.

## Preview Testing Handbook: [https://appsec.guide](https://appsec.guide) 🌐

## Why is this needed? ✨

- 📃 The documentation for configuring and optimizing existing tools is often not developer-friendly, as it is often meant
for security professionals. This is especially the case when it comes to fuzzing utilities. This can lead to frustration
and poor adoption of security tools that should be straightforward to configure.
- ⚙️ Even if the tool is easy to configure locally, it can be difficult to configure them in CI/CD pipelines.
Often, security tools are set up by following online documentation, but their configuration is rarely optimized.
This can lead to a noisy tool that is more difficult to maintain than worth.
- 🧠 We aim to make it as easy and straightforward as possible to set up security tools effectively. In doing so, we also
hope to demystify static and dynamic analysis techniques such as fuzzing and taint analysis.

## Chapters

### ✅ Released

|Topic|Announcing Blog Post|Year|
|---|---|---|
|[Semgrep](https://appsec.guide/docs/static-analysis/semgrep/)| [Announcing the Trail of Bits Testing Handbook](https://blog.trailofbits.com/2023/07/26/announcing-the-trail-of-bits-testing-handbook/)|2023|
|[CodeQL](https://appsec.guide/docs/static-analysis/codeql/)| [Say hello to the next chapter of the Testing Handbook!](https://blog.trailofbits.com/2023/12/11/say-hello-to-the-next-chapter-of-the-testing-handbook/)|2023|

### 🚧 Under construction

- Fuzzing
- Burp Suite Professional
- Rust

## How to contribute

If you would like to contribute to the Testing Handbook, here are some guidelines to help you get started:

1. **Add a New Tool**: If you want to cover a new tool in the Testing Handbook,
propose a topic in GitHub Issues. Afterward, you can work on a new pull request.
1. **Improve Existing Chapters**: If you have an idea to make a specific chapter better,
you can add a GitHub issue.
1. **Pick Up Small Tasks**: If you don't have much time but still want to contribute,
you can pick up any small task from the GitHub issues list.
1. **Report Issues**: If you find a small technical issue or a typo,
create a new GitHub issue and/or fix it in the new pull request.

### Quick setup for convenient development

1. Install Hugo in your system

    ```shell
    brew install hugo
    ```

2. Clone the repo

    ```shell
    git clone --recurse-submodules https://github.com/trailofbits/testing-handbook.git
    ```

3. Create a new branch or select a branch you want to work on

   ```shell
   cd testing-handbook
   # then
   git checkout -b name-of-your-new-branch
   # or
   git checkout name-of-existing-branch

4. Run the Hugo server with drafts turned on (`-D`) from the project's root directory.
Your browser will be automatically refreshed with changes whenever you save a file.

    ```shell
    hugo server -D
    ```

5. Add a new tool as "doc", and run the following from the project's root directory.

    ```shell
    hugo new docs/<name of tool>
    ```

    **Note**: This project uses the same hugo template as [zkdocs](https://www.zkdocs.com/). The template refers to each
    new page as a "doc," as opposed to a post. This is why you'd want to type `hugo new docs/<name of tool>` and not `post/my-new-post`.

6. Edit, add, and create pull requests to merge your changes into `main`.

7. ❗Keep in mind that when you merge your PR into `main`, the content goes live in <https://appsec.guide>.
    Our current policy forces at least one review before merging.

8. For updates to the home page, edit [content/_index.md](content/_index.md)

## Guidelines

- The format should be consistent between each "doc." When adding a new doc (i.e., when adding a new tool), follow the
  template in [content/docs/template.md](content/docs/template.md). Send a PR for this file with suggested changes as needed.

- Create a new branch with your changes, and create a PR to merge into `main` when you are done.

- The GitHub workflow in this repository verifies the correctness of Markdown files through three checks:
  1. **Markdown Link Check**: This step extracts links from Markdown files and verifies if they are valid and accessible.
    It uses the [github-action-markdown-link-check](https://github.com/gaurav-nelson/github-action-markdown-link-check) action.
  2. **Markdown Linter**: This step ensures that Markdown files adhere to the desired style and formatting rules.
    It uses a custom configuration file (`.github/workflows/.markdownlint.jsonc`) and the
     [markdownlint-cli2-action](https://github.com/DavidAnson/markdownlint-cli2-action) action.
     Use the [markdownlint](https://marketplace.visualstudio.com/items?itemName=DavidAnson.vscode-markdownlint) extension
     with Visual Studio Code for better user experience while working on the Testing Handbook.
  3. **Spellcheck**: This step checks the spelling in Markdown files
     (built on top of [retext](https://github.com/retextjs/retext) and [remark](https://github.com/remarkjs/remark)).
     It uses a custom dictionary file (`.github/workflows/dictionary.txt`) and the
     [tbroadley/spellchecker-cli-action](https://github.com/tbroadley/spellchecker-cli-action) action.

- Familiarize yourself with the [Hugo Book theme](https://hugo-book-demo.netlify.app/)
as it has a couple of nice features (buttons, etc.)
- Reach out in [#testing-handbook](https://empirehacking.slack.com/archives/C06CSLSQAMB) Empire Hacking Slack if you have any questions.

## Editing

### Writing Guidelines

- The term "Testing Handbook" should be capitalized any time it appears on the website (whether in a header/subheader or running text),
since it is the title of a document. But if you'd like to avoid the capitalization because it looks strange, you can substitute
"Testing Handbook" for "this handbook" (since it's clear enough what the title of the handbook is).

### Workflow: From Google Docs

1. Make your document viewable via a link share.
2. Create a Google account or use your private one (If you use this method, then your document should be regarded as public, but unpublished).
3. Install [Docs to Markdown](https://workspace.google.com/marketplace/app/docs_to_markdown/700168918607).
This addon works better than pandoc.
4. Open the document and make a copy.
5. Open the copy and run the Addon.
6. Export the markdown and apply fixes:
   - Search for occurences of `<code>` or `<strong>` or any other html tags
   - Replace HTML tables with markdown ones (<https://jmalarcon.github.io/markdowntables/>)
   - If you split your document, fix internal links.
   - Add missing images.
   - Fix `&lt;`, …, “, ’
   - Adjust markdown captions ## -> #
   - Verify missing formatting in PRO TIPs
   - . at the end of fig captions?
   - Note that index bundles do not use the "slug"

### Custom enviornments

```md
{{< customFigure "Caption" >}}
{{< /customFigure >}}

{{< resourceFigure "cov1.png" >}}
{{< /resourceFigure >}}

{{< hint info >}}
{{< /hint >}}
```
