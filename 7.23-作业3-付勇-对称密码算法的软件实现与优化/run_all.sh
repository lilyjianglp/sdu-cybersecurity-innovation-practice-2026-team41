#!/usr/bin/env bash
set -euo pipefail

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
./build/test_aes128
./build/test_aes128_ttable
./build/test_aes128_avx2
./build/test_aes128_aesni
./build/test_aes128_ctr
./build/test_aes128_gcm
./build/test_aes128_xts
./build/bench_aes128_xts
