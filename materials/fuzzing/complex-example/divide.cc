#include <stdint.h>
#include <stdlib.h>

double divide(uint32_t numerator, uint32_t denominator) {
    // Bug: No check if denominator is zero
    return numerator / denominator;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure exactly 2 4-byte numbers (numerator and denominator) are read
    if(size != 2 * sizeof(uint32_t)){
        return 0;
    }

    // Split input into numerator and denominator
    int numerator = *(uint32_t*)(data);
    int denominator = *(uint32_t*)(data + sizeof(uint32_t));

    divide(numerator, denominator); 
    
    return 0;
}
