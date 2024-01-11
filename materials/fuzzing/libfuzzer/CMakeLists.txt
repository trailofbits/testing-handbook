project(BuggyProgram)
cmake_minimum_required(VERSION 3.0)

add_executable(buggy_program main.cc)

add_executable(fuzz main.cc harness.cc)
target_compile_definitions(fuzz PRIVATE NO_MAIN=1)
target_compile_options(fuzz PRIVATE -g -O2 -fsanitize=fuzzer)
target_link_libraries(fuzz -fsanitize=fuzzer)

add_executable(fuzz_exec main.cc harness.cc ${CMAKE_CURRENT_SOURCE_DIR}/../coverage-analysis/execute-rt.cc)
target_compile_definitions(fuzz_exec PRIVATE NO_MAIN)
target_compile_options(fuzz_exec PRIVATE -O2 -fprofile-instr-generate -fcoverage-mapping)
target_link_libraries(fuzz_exec -fprofile-instr-generate)


add_executable(fuzz_exec_gcov main.cc harness.cc ${CMAKE_CURRENT_SOURCE_DIR}/../coverage-analysis/execute-rt.cc)
target_compile_definitions(fuzz_exec_gcov PRIVATE NO_MAIN)
target_compile_options(fuzz_exec_gcov PRIVATE -O2 -ftest-coverage -fprofile-arcs)
target_link_libraries(fuzz_exec_gcov -ftest-coverage -fprofile-arcs)


