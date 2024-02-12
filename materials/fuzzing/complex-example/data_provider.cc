#include <stdint.h>
#include <stdlib.h>
#include "./FuzzedDataProvider.h"

char* concat(const char* inputStr, size_t inputStrLen, 
    const char* anotherStr, size_t anotherStrLen, 
    size_t allocation_size) {

    if (allocation_size <= 1 || allocation_size > 1 << 16) {
        return NULL;
    }

    char* result = (char*)malloc(allocation_size);

    if (result == NULL) {
        return NULL;
    }

    memcpy(result, inputStr, inputStrLen);
    memcpy(result + inputStrLen, anotherStr, anotherStrLen);

    return result;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fuzzed_data(data, size);

    size_t allocation_size = fuzzed_data.ConsumeIntegral<size_t>();

    std::vector<char> str1 =
        fuzzed_data.ConsumeBytesWithTerminator<char>(32, 0xFF);

    std::vector<char> str2 =
        fuzzed_data.ConsumeBytesWithTerminator<char>(32, 0xFF);

    char* concatenated = concat(&str1[0], str1.size(), &str2[0], str2.size(), allocation_size);
    if (concatenated != NULL) {
        free(concatenated); 
    }
    
    return 0;
}
