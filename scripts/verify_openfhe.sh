#!/bin/bash
set -e

echo "=== OpenFHE 1.5.1 Verification ==="

# Check installation directory
echo "Checking installation directory..."
if [ -d "/usr/local/openfhe-stock" ]; then
    echo "✓ /usr/local/openfhe-stock exists"
else
    echo "✗ /usr/local/openfhe-stock not found"
    exit 1
fi

# Check libraries
echo "Checking libraries..."
for lib in libOPENFHEcore.so libOPENFHEpke.so libOPENFHEbinfhe.so; do
    if [ -f "/usr/local/openfhe-stock/lib/$lib" ]; then
        echo "✓ $lib found"
    else
        echo "✗ $lib not found"
        exit 1
    fi
done

# Check headers (openfhe.h is under pke/)
echo "Checking headers..."
if [ -f "/usr/local/openfhe-stock/include/openfhe/pke/openfhe.h" ]; then
    echo "✓ openfhe.h found"
else
    echo "✗ openfhe.h not found"
    exit 1
fi

# Check CMake config
echo "Checking CMake configuration..."
if [ -f "/usr/local/openfhe-stock/lib/cmake/OpenFHE/OpenFHEConfig.cmake" ] || \
   [ -f "/usr/local/openfhe-stock/lib/OpenFHE/OpenFHEConfig.cmake" ]; then
    echo "✓ OpenFHEConfig.cmake found"
else
    echo "✗ OpenFHEConfig.cmake not found"
    exit 1
fi

# Compile and run test program
echo "Compiling test program..."
cat > /tmp/verify_openfhe.cpp << 'TESTEOF'
#include <openfhe.h>
#include <iostream>
#include <vector>
using namespace lbcrypto;
int main() {
    CCParams<CryptoContextCKKSRNS> params;
    params.SetSecurityLevel(HEStd_128_classic);
    params.SetRingDim(16384);
    params.SetScalingModSize(40);
    params.SetMultiplicativeDepth(2);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(params);
    cc->Enable(PKE); cc->Enable(KEYSWITCH); cc->Enable(LEVELEDSHE);
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    std::vector<double> vals = {1.0, 2.0, 3.0, 4.0};
    auto pt = cc->MakeCKKSPackedPlaintext(vals);
    auto ct = cc->Encrypt(keys.publicKey, pt);
    Plaintext dec;
    cc->Decrypt(keys.secretKey, ct, &dec);
    std::cout << "OK" << std::endl;
    return 0;
}
TESTEOF

/usr/bin/g++ -std=c++17 /tmp/verify_openfhe.cpp -o /tmp/verify_openfhe \
  -I/usr/local/openfhe-stock/include/openfhe \
  -I/usr/local/openfhe-stock/include/openfhe/core \
  -I/usr/local/openfhe-stock/include/openfhe/pke \
  -I/usr/local/openfhe-stock/include/openfhe/binfhe \
  -L/usr/local/openfhe-stock/lib \
  -lOPENFHEpke -lOPENFHEcore -lOPENFHEbinfhe -fopenmp \
  -Wl,-rpath,/usr/local/openfhe-stock/lib

echo "Running test program..."
/tmp/verify_openfhe

echo ""
echo "=== All OpenFHE checks passed ==="
