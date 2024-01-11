#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __AFL_COMPILER
#include "argv-fuzz-inl.h"

__AFL_FUZZ_INIT();

void check_buf(char *buf, size_t buf_len) {
    if(buf_len > 0 && buf[0] == 'a') {
        if(buf_len > 1 && buf[1] == 'b') {
            if(buf_len > 2 && buf[2] == 'c') {
                abort();
            }
        }
    }
}

int main(int argc, char *argv[]) {
#ifdef __AFL_COMPILER
    unsigned char *buf;
    __AFL_INIT();
    buf = __AFL_FUZZ_TESTCASE_BUF;
    AFL_INIT_ARGV_PERSISTENT(buf);
#endif

#ifdef __AFL_COMPILER
    while (__AFL_LOOP(1000)) {
#endif

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_string>\n", argv[0]);
        return 1;
    }

    char *input_buf = argv[1];
    size_t len = strlen(input_buf);

    check_buf(input_buf, len);

#ifdef __AFL_COMPILER
    }
#endif

    return 0;
}