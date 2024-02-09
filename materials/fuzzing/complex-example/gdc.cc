#include <cstdint>
#include <cstddef>

int gcd(uint64_t a, uint64_t b) {
    if (b == 0)
        return a;
    return gcd(b, a % b);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < sizeof(uint64_t) * 2) {
        return 0;
    }

    int a = *(uint64_t*)data;
    int b = *(uint64_t*)(data + sizeof(uint64_t));

    gcd(a, b);
    return 0;
}
