#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void check_buf(char *buf, size_t buf_len) {
    char *last;

    if(buf_len > 0 && buf[0] == 'a') {
        if(buf_len > 1 && buf[1] == 'b') {
            if(buf_len > 2 && buf[2] == 'c') {
                last = (char*)malloc(1 * sizeof(char));
                last[0] = 'c';
                last[1] = '\0';
                printf("%s", last);
                free(last);
            }
        }
    }
}

#ifndef NO_MAIN
int main() {
    char target[] = "123";
    size_t len = strlen(target);
    check_buf(target, len);
    return 0;
}
#endif // NO_MAIN
