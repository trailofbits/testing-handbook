If you are fuzzing C projects that produce static libraries, you can follow this recipe:

1. Read the `INSTALL` file in the project's codebase (or other appropriate documentation) and find out how to create a static library.
2. Set the compiler to Clang, and pass additional flags to the compiler during compilation.
3. Build the static library, {{ (.Get 0) }}, and pass the flag `-fsanitize=fuzzer-no-link `to the C compiler, which enables fuzzing-related instrumentations, without linking in the fuzzing engine. The runtime, which includes the `main` symbol, is linked later when using the `-fsanitize=fuzzer` flag. The build step will create a static library, which we will refer to as `$static_library`. The environment variable enables ASan to detect memory corruption.
4. Find the compiled static library from step 3 and call: {{ (.Get 1) }}.
5. You can start fuzzing by calling {{ (.Get 2) }}.

Let's go through these instructions for the well-known libpng library. First, we get the source code:


```shell
curl -L -O https://downloads.sourceforge.net/project/libpng/libpng16/1.6.37/libpng-1.6.37.tar.xz
tar xf libpng-1.6.37.tar.xz
cd libpng-1.6.37/
```