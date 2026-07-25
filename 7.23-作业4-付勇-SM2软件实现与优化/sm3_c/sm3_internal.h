#ifndef SM3_INTERNAL_H
#define SM3_INTERNAL_H

#include "sm3.h"


void sm3_compress_ref(
    uint32_t state[SM3_STATE_WORDS],
    const uint8_t block[SM3_BLOCK_SIZE]
);

void sm3_compress_arm64_neon(
    uint32_t state[SM3_STATE_WORDS],
    const uint8_t block[SM3_BLOCK_SIZE]
);

void sm3_compress_arm64_asm(
    uint32_t state[SM3_STATE_WORDS],
    const uint8_t block[SM3_BLOCK_SIZE]);

#endif 
