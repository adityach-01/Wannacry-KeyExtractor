#include <vector>
#include <iostream>
#include <cstdint>
#include <cstdio>
#include "KeyExtractor.hpp"

// #include <boost>
#define MINIMAL_ENTROPY 0.7

class BLOBHEADER
{
public:
    // uint32_t bType, bVersion, reserved, aiKeyAlg;
    uint8_t bType;
    uint8_t bVersion;
    uint16_t reserved;
    uint32_t aiKeyAlg;
};

class RSAPUBKEY
{
public:
    uint32_t magic, bitlen, pubexp;
};

std::vector<uint8_t> init_buffer(FILE *fp, int size)
{
    std::vector<uint8_t> Buf;
    Buf.resize(size);

    fread(&Buf[0], 1, size, fp);

    return Buf;
}

void dumpHex(const char *Name, uint8_t const *Data, size_t const Len)
{
    printf("%s:", Name);
    for (size_t i = 0; i < Len; ++i)
    {
        if ((i % 16 == 0))
        {
            printf("\n");
        }
        printf("%02X ", Data[i]);
    }
    printf("\n====\n");
}

bool isPrime(BigInt const &n)
{
    static std::mt19937 RandEng(std::random_device{}());
    return boost::multiprecision::miller_rabin_test(n, 25, RandEng);
}

double normalizedEntropy(uint8_t const *Data, const size_t Len)
{
    // Initialized at 0 thanks to the uint32_t constructor.
    std::array<uint32_t, 256> Hist;

    std::fill(Hist.begin(), Hist.end(), 0);

    // len is the size of the prime in bytes
    for (size_t i = 0; i < Len; ++i)
    {
        ++Hist[Data[i]];
    }

    double Ret = 0.0;
    for (uint32_t Count : Hist)
    {
        if (Count)
        {
            double const P = (double)Count / (double)Len;
            Ret += P * std::log(P);
        }
    }
    if (Ret == 0.0)
    {
        // Or we would have -0.0 with the line below!
        return 0.0;
    }

    return -Ret / std::log(256.);
}

BigInt check(BigInt N, std::vector<uint8_t> &Buf, int PrimeSize)
{

    // considers both big endian and small endian notation
    double entropy = normalizedEntropy(&Buf[0], PrimeSize);

    if(entropy < MINIMAL_ENTROPY) return 0;

    auto P = getInteger(&Buf[0], PrimeSize, false);
    if (P >= 2 && (N % P == 0))
    {
        return P;
    }

    // if N is correct public key, then prime testing of P is neot needed
    P = getInteger(&Buf[0], PrimeSize, true);
    if (P >= 2 && (N % P == 0))
    {
        return P;
    }

    // is not a valid number
    return 0;
}

BigInt getInteger(uint8_t const *const Data, size_t const Len, bool MsvFirst /* = false */)
{
    BigInt n;
    boost::multiprecision::import_bits(n, Data, Data + Len, 8, MsvFirst);

    return n;
}

void printBuffer(std::vector<uint8_t> Buf)
{
    int sz = Buf.size();

    for (int i = 0; i < sz; i++)
    {
        if (i % 16 == 0)
        {
            std::cout << '\n';
        }

        printf("%02X ", Buf[i]);
    }

    std::cout << "\n==========\n";
}

// add the bigInt Modolus
BigInt readAndCheckFile(const char *path, int prime_size, BigInt N)
{
    std::vector<uint8_t> Buf;
    FILE *fp = fopen(path, "rb");
    if (!fp)
    {
        std::cout << "Error opening dump file...." << std::endl;
        exit(0);
    }

    Buf = init_buffer(fp, prime_size);

    // printBuffer(Buf);

    fseek(fp, prime_size, SEEK_SET);

    // check the number in buffer
    auto P = check(N, Buf, prime_size);
    if (P != 0)
        return P;

    long long numBytes = 0;
    int numMB = 0;
    int numKb = 0;

    while (!feof(fp) && !ferror(fp))
    {
        uint8_t byte;
        fread(&byte, sizeof(uint8_t), 1, fp);

        Buf.erase(Buf.begin());
        Buf.push_back(byte);

        numBytes++;

        if (numBytes == 1024)
        {
            numBytes = 0;
            numKb++;

            if (numKb == 1024)
            {
                numKb = 0;
                numMB++;
                std::cout << "Progress..... " << "Read " << numMB << " MB" << std::endl;
            }
        }

        // check the number buffer
        auto P = check(N, Buf, prime_size);
        if (P != 0)
        {   
            // found a prime, now return this prime for further processing
            return P;
        }
    }

    // means no prime number that divides modulus present in the file
    return 0;
}

std::error_code getLastErrno()
{
    return std::error_code{errno, std::system_category()};
}

std::vector<uint8_t> readFile(const char *path, std::error_code &EC)
{
    std::vector<uint8_t> Ret;
    FILE *f = fopen(path, "rb");
    if (!f)
    {
        EC = getLastErrno();
        return Ret;
    }
    fseek(f, 0, SEEK_END);
    const long Size = ftell(f);
    fseek(f, 0, SEEK_SET);
    Ret.resize(Size);
    if (fread(&Ret[0], 1, Size, f) != Size)
    {
        EC = getLastErrno();
        return Ret;
    }
    EC = std::error_code{};
    return Ret;
}

std::vector<uint8_t> getDataFromInteger(BigInt const &N, bool MsvFirst /* = false */)
{
    std::vector<uint8_t> Ret;
    boost::multiprecision::export_bits(N, std::back_inserter(Ret), 8, MsvFirst);
    return Ret;
}

BigInt mulInv(BigInt a, BigInt b)
{
    BigInt b0 = b, t, q;
    BigInt x0 = 0, x1 = 1;
    if (b == 1)
        return 1;
    while (a > 1)
    {
        q = a / b;
        t = b, b = a % b, a = t;
        t = x0, x0 = x1 - q * x0, x1 = t;
    }
    if (x1 < 0)
        x1 += b0;
    return x1;
}

// void dumpHex(string head, )

std::pair<BigInt, int> getModolusfromPublicKey(std::string public_key)
{
    std::error_code EC;
    std::vector<uint8_t> keyData = readFile(public_key.c_str(), EC);
    if (EC)
    {
        std::cerr << "Error reading public key file: " << EC.message() << std::endl;
        exit(0);
    }

    // Check that this is an RSA2 key of 2048 bits
    size_t idx = 0;
    dumpHex("blob_header", &keyData[idx], 8);
    idx += 8;
    dumpHex("pub_key", &keyData[idx], 12);
    if (*((uint32_t *)&keyData[idx]) == 0x52534131)
    {
        printf("Invalid RSA key!\n");
        return {1, 1};
    }

    idx += 12;

    uint32_t keyLen = *(((uint32_t *)&keyData[0]) + 3) / 8;
    uint32_t subkeyLen = (keyLen + 1) / 2;
    printf("Keylen: %d\n", keyLen);

    // Get N, which is the modolus
    dumpHex("N", &keyData[idx], keyLen);
    // what happens when it is made true

    // considering little endian notation
    const auto N = getInteger(&keyData[idx], keyLen);

    std::vector<uint8_t> Nval = getDataFromInteger(N);
    dumpHex("N that matters", &Nval[0], keyLen);

    // return the modolus
    return {N, subkeyLen};
}


void writeIntegerToFile(FILE *f, BigInt const &N, uint32_t padSize)
{
    auto NData = getDataFromInteger(N);
    // Padding with zeros
    NData.resize(padSize);
    if (fwrite(&NData[0], 1, NData.size(), f) != NData.size())
    {
        std::cerr << "Error while writing!" << std::endl;
    }
}

static bool genRSAKey(BigInt const &N, BigInt const &P, uint32_t PrimeSize, const char *OutFile)
{
    FILE *f = fopen(OutFile, "wb");
    if (!f)
    {
        std::cerr << "Unable to open '" << OutFile << "'" << std::endl;
        return false;
    }

    BLOBHEADER header;
    header.bType = 7; // 1 byte
    header.bVersion = 2; // 1 byte
    header.reserved = 0; // 2 byte
    header.aiKeyAlg = 0x0000a400; // 4 byte
    fwrite(&header, 1, sizeof(BLOBHEADER), f);

    auto const e = 0x10001;

    RSAPUBKEY pubKey;
    pubKey.magic = 0x32415352;
    pubKey.bitlen = (PrimeSize * 2) * 8;
    pubKey.pubexp = e;
    fwrite(&pubKey, 1, sizeof(RSAPUBKEY), f);

    // Thanks to the wine source code for this format!
    BigInt const Q = N / P;
    BigInt const Phi = boost::multiprecision::lcm(P - 1, Q - 1);
    BigInt const d = mulInv(e, Phi);
    BigInt const dP = d % (P - 1);
    BigInt const dQ = d % (Q - 1);
    BigInt const iQ = mulInv(Q, P);
    writeIntegerToFile(f, N, PrimeSize * 2);
    writeIntegerToFile(f, P, PrimeSize);
    writeIntegerToFile(f, Q, PrimeSize);
    writeIntegerToFile(f, dP, PrimeSize);
    writeIntegerToFile(f, dQ, PrimeSize);
    writeIntegerToFile(f, iQ, PrimeSize);
    writeIntegerToFile(f, d, PrimeSize * 2);

    fclose(f);
    return true;
}

int main(int argc, char *argv[])
{   
    // has a command line argument
    bool customPath = false;
    if(argc > 1){
        char *flag = argv[1];
        if(!strcmp(flag, "--custom")) customPath = true;

        
    }

    // get the working directory and the PID of the wannacry proccess
    std::string CurWorkingDir = "data/";


    std::string PubKey, PrivateKey, DumpPath;

    if(customPath){
        std::cout << "Enter Public Key path : ";
        std::cin >> PubKey;

        if(PubKey.length() == 0) PubKey = CurWorkingDir + "00000000.pky";

        std::cout << "Enter Private Key path : ";
        std::cin >> PrivateKey;

        if(PrivateKey.length() == 0) PrivateKey = CurWorkingDir + "00000000.dky";

        std::cout << "Enter Dump file path : ";
        std::cin >> DumpPath;

        if(DumpPath.length() == 0) DumpPath = CurWorkingDir + "ProcessDump.dmp";
    }else{
        PubKey = CurWorkingDir + "00000000.pky";
        PrivateKey = CurWorkingDir + "00000000.dky";
        // DumpPath = CurWorkingDir + "ProcessDump.dmp";
        std::cout << "Enter Dump File path : " << std::endl;
        std::cin >> DumpPath;
    }


    std::string pubPath = PubKey;
    auto data = getModolusfromPublicKey(pubPath);

    int prime_size = data.second;
    auto N = data.first;


    std::cout << "Prime Size is " << prime_size << " bytes" << std::endl;

    std::string dumpPath = DumpPath;

    // create the dump file using procdump executable
    
    auto P = readAndCheckFile(dumpPath.c_str(), prime_size, N);

    if (P == 0)
    {
        std::cout << "No prime number exist in the file that divides N" << std::endl;
    }
    else
    {
        // prime found, gen private key
        std::cout << "Found the prime!!" << std::endl;

        const std::vector<uint8_t> primeVal = getDataFromInteger(P);

        dumpHex("First Prime Number (P)", &primeVal[0], prime_size);

        auto Q = N / P;
        const std::vector<uint8_t> otherPrime = getDataFromInteger(Q);

        dumpHex("Second Prime Number (Q)", &otherPrime[0], prime_size);


        std::cout << "Generating Private Key file.........." << std::endl;
        genRSAKey(N, P, prime_size, PrivateKey.c_str());
        std::cout << "Private Key file in " << CurWorkingDir << "/" << PrivateKey << std::endl;
    }

    return 0;
}
