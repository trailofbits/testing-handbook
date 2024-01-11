#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __AFL_COMPILER
#include "argv-fuzz-inl.h"
#endif

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
    AFL_INIT_ARGV();
#endif

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_string>\n", argv[0]);
        return 1;
    }

    char *input_buf = argv[1];
    size_t len = strlen(input_buf);

    check_buf(input_buf, len);

    return 0;
}