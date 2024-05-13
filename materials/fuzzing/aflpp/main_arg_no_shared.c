#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __AFL_COMPILER
#include "argv-fuzz-inl.h"
//__AFL_FUZZ_INIT();
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

//extern __attribute__((visibility("default"))) int __afl_connected;

int main(int argc, char *argv[]) {
#ifdef __AFL_COMPILER

    //__AFL_INIT(); // is this required? when is it? deferred fork server? apparently yes

#endif
    //(fprintf(stderr, "__afl_connected: %d\n",__afl_connected);

    
    int its = 0;
    while (__AFL_LOOP(1000)) {
        its++;

if (its > 800) {
        fprintf(stdout, "iters: %d\n", its);
}

        AFL_INIT_ARGV();

        if (argv == NULL) {
            continue;
        }

        if (argc < 2) {
            //fprintf(stderr, "Usage: %s <input_string>\n", argv[0]);
            //return 1;
            continue;
        }

        char *input_buf = argv[1];
        size_t len = strlen(input_buf);
        check_buf(input_buf, len);
       

    }

      

    


    return 0;
}