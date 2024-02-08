Let's assume we are using CMake to build the program mentioned in the [introduction]({{ (.Get 0) }}). We add a CMake target that builds the `main.cc` and `harness.cc` and links the target together with AFL++. Note that we are excluding the main function through the `NO_MAIN` flag; otherwise, the program would have two main functions.


{{< customFigure "CMake example" >}}
```cmake
project(BuggyProgram)
cmake_minimum_required(VERSION 3.0)

add_executable(buggy_program main.cc)

add_executable(fuzz main.cc harness.cc)
target_compile_definitions(fuzz PRIVATE NO_MAIN=1)
target_compile_options(fuzz PRIVATE -g -O2 -fsanitize=fuzzer)
target_link_libraries(fuzz -fsanitize=fuzzer)
```
{{< /customFigure >}}