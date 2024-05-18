#include <vector>

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/miller_rabin.hpp>

// Use boost::multiprecision for big int handling. It has the advantage to be
// header-only and saves us the pain of supporting third-party libraries within
// windows...

typedef boost::multiprecision::cpp_int BigInt;

void writeIntegerToFile(FILE* f, BigInt const& N, uint32_t padSize);
BigInt mulInv(BigInt a, BigInt b);
BigInt getInteger(uint8_t const* const Data, size_t const Len, bool MsvFirst  = false);
std::vector<uint8_t> getDataFromInteger(BigInt const& N, bool MsvFirst = false);

bool isPrime(BigInt const &n);
