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
int main(int argc, char *argv[]) {
    char input_buf[MAX_BUF_SIZE];

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    FILE *file = fopen(argv[1], "r");
    if (file == NULL) {
        return 1;
    }

    if (fgets(input_buf, MAX_BUF_SIZE, file) == NULL) {
        if (!feof(file)) { // Check for reading error and not end of file
            fclose(file);
            return 1;
        }
    }

    fclose(file);

    size_t len = strlen(input_buf);
    check_buf(input_buf, len);
    return 0;
}