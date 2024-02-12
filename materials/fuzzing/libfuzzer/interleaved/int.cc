#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>

int32_t add(int32_t a, int32_t b);
int32_t subtract(int32_t a, int32_t b);
int32_t multiply(int32_t a, int32_t b);
int32_t divide(int32_t a, int32_t b);

int32_t add(int32_t a, int32_t b) {
    return a + b;
}

int32_t subtract(int32_t a, int32_t b) {
    return a - b;
}

int32_t multiply(int32_t a, int32_t b) {
    return a * b;
}

int32_t divide(int32_t a, int32_t b) {
    // Avoid division by zero and int overflow
    if (b != 0 && !(a == INT_MIN && b == -1)) {
        return a / b;
    }
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1 + 2 * sizeof(int32_t)) {
        return 0;
    }

    uint8_t mode = data[0];
    int32_t numbers[2];
    int32_t r = 0;
    memcpy(numbers, data + 1, 2 * sizeof(int32_t));

    // We select functions based on the first byte of the fuzzing data
    switch (mode % 4) {
    case 0:
        r = add(numbers[0], numbers[1]);
        break;
    case 1:
        r = subtract(numbers[0], numbers[1]);
        break;
    case 2:
        r = multiply(numbers[0], numbers[1]);
        break;
    case 3:
        r = divide(numbers[0], numbers[1]);
        break;
    }

    printf("%d", r);

    return 0;
}
