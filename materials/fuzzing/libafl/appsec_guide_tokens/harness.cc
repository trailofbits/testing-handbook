#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
void check_buf(char *buf, size_t buf_len);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  check_buf((char*) data, size);
  return 0;
}

