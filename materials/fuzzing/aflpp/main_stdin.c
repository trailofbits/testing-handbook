#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF_SIZE 100

void check_buf(char *buf, size_t buf_len) {
    if(buf_len > 0 && buf[0] == 'a') {
        if(buf_len > 1 && buf[1] == 'b') {
            if(buf_len > 2 && buf[2] == 'c') {
                abort();
            }
        }
    }
}

int main() {
    char input_buf[MAX_BUF_SIZE];

    if (fgets(input_buf, MAX_BUF_SIZE, stdin) == NULL) {
        return 1;
    }

    size_t len = strlen(input_buf);
    check_buf(input_buf, len);
    return 0;
}