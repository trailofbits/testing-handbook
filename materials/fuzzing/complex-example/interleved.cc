#include <stdint.h>
#include <stdlib.h>
#include <string.h>

double add(double a, double b);
double subtract(double a, double b);
double multiply(double a, double b);
double divide(double a, double b);

double add(double a, double b) {
    return a + b;
}

double subtract(double a, double b) {
    return a - b;
}

double multiply(double a, double b) {
    return a * b;
}

double divide(double a, double b) {
    if (b != 0.0) {  // Avoid division by zero
        return a / b;
    }

    return 0.0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1 + 2 * sizeof(double)) {
        return 0;
    }

    uint8_t mode = data[0];
    double numbers[2];
    memcpy(numbers, data + 1, 2 * sizeof(double));

    // We select functions based on the first byte of the fuzzing data
    switch (mode % 4) {
    case 0:
        add(numbers[0], numbers[1]);
        break;
    case 1:
        subtract(numbers[0], numbers[1]);
        break;
    case 2:
        multiply(numbers[0], numbers[1]);
        break;
    case 3:
        divide(numbers[0], numbers[1]);
        break;
    }

    return 0;
}