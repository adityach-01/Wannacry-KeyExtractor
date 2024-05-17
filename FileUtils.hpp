#ifndef FILE_SYSTEM_UTILS
#define FILE_SYSTEM_UTILS

#include "Process.hpp"

bool fileHasString(const char *path, const char *str);
uint8_t const* memmem(const uint8_t *haystack, size_t hlen, const uint8_t *needle, size_t nlen);
std::vector<uint8_t> readFile(const char* path, std::error_code& EC);
#endif