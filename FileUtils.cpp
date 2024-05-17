#include <iostream>
#include "Process.hpp"
#include <array>
#include <cstdint>
#include <cstdio>
#include <string>
#include <cmath>
#include <string.h>
#include <algorithm>
#include <memory.h>

uint8_t const* memmem(const uint8_t *haystack, size_t hlen, const uint8_t *needle, size_t nlen)
{
	if (nlen == 0) {
		return NULL;
	}
	uint8_t const* curPtr = haystack;
	uint8_t const* const endPtr = haystack + hlen;
	uint8_t const firstByte = *needle;
	do {
		curPtr = std::find(curPtr, endPtr, firstByte);
		if (curPtr < endPtr) {
			if (((uintptr_t)endPtr-(uintptr_t)curPtr) < nlen) {
				return nullptr;
			}
			if (memcmp(curPtr, needle, nlen) == 0) {
				return curPtr;
			}
		}
		++curPtr;
	} while (curPtr < endPtr);

	return nullptr;
}



std::vector<uint8_t> readFile(const char* path, std::error_code& EC)
{
  std::vector<uint8_t> Ret;
  FILE* f = fopen(path, "rb");
  if (!f) {
    EC = getLastErrno();
    return Ret;
  }
  fseek(f, 0, SEEK_END);
  const long Size = ftell(f);
  fseek(f, 0, SEEK_SET);
  Ret.resize(Size);
  if (fread(&Ret[0], 1, Size, f) != Size) {
    EC = getLastErrno();
    return Ret;
  }
  EC = std::error_code{};
  return Ret;
}

bool fileHasString(const char* path, const char* str)
{
  std::error_code EC;
  auto Data = readFile(path, EC);
  if (EC) {
    std::cerr << "error reading '" << path << "': " << EC.message() << std::endl;
    return false;
  }
  return memmem(&Data[0], Data.size(), (const uint8_t*)str, strlen(str)) != NULL;
}