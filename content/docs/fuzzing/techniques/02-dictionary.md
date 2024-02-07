---
title: "Dictionary fuzzing"
slug: dictionary
summary: "TODO"
weight: 2
---

<!--TODO rename this section to Fuzzing Dictionaries-->




#### Generating a dictionary {#generating-a-dictionary}

There are several ways to generate a dictionary.



* LLMs (large language models): Tools like OpenAI’s ChatGPT are helpful in generating a dictionary for your fuzzing task. However, be aware of LLM hallucinations. If the LLM proposes a feature not mentioned in this handbook, check first if it really exists. Try the following LLM prompt with the task `PNG parser`:
    ```text {.code-fence-wrap}
    A dictionary can be used to guide the fuzzer. A dictionary is passed as a file to the fuzzer usually.
    The simplest input accepted by libFuzzer is an ASCII text file where each line consists of a quoted string. Strings can contain escaped byte sequences like "\xF7\xF8". Optionally, a key-value pair can be used like hex_value="\xF7\xF8" for documentation purposes. Comments are supported by starting a line with #. Write me an example dictionary file for a <fuzzing task>:
    ```
* Header files: If you found C header file that contains relevant strings, then they can be extracted using the following command:
    ```shell
    grep -o '".*"' header.h > header.dict
    ```
* Man pages: If the project you are fuzzing has man pages, then you can use these to generate a dictionary. This is especially helpful when fuzzing a CLI.
    ```shell
    man curl | grep -oP '^\s*(--|-)\K\S+' | sed 's/[,.]$//' | sed 's/^/"&/; s/$/&"/' | sort -u > man.dict
    ```
* AFL++ [AUTODICTIONARIES](https://github.com/AFLplusplus/AFLplusplus/blob/108fb0b29ad1586e668ba23e23a0eb1a13c45c49/instrumentation/README.lto.md#autodictionary-feature): If you are using `afl-clang-lto`, then AFL++ will automatically generate a dictionary based on the binary that is being fuzzed.
* If you are not using AFL++, then you might want to use the strings binary to generate dictionary:
    ```shell
    strings ./binary | sed 's/^/"&/; s/$/&"/' > strings.dict
    ```