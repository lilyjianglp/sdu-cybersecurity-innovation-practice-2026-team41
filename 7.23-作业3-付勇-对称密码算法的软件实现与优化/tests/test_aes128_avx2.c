#include "aes128.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint64_t xorshift64(uint64_t *state) {
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

static void fill_deterministic(uint8_t *buffer, size_t size, uint64_t *state) {
    for (size_t i = 0; i < size; ++i) {
        if ((i & 7U) == 0U) {
            (void)xorshift64(state);
        }
        buffer[i] = (uint8_t)(*state >> ((i & 7U) * 8U));
    }
}

static int check_eight_standard_blocks(void) {
    static const uint8_t key[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const uint8_t plaintext[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    static const uint8_t expected[16] = {
        0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
        0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a
    };

    uint8_t input[8 * AES128_BLOCK_SIZE];
    uint8_t output[sizeof(input)];
    aes128_key_t ctx;

    for (size_t i = 0; i < 8; ++i) {
        memcpy(input + i * AES128_BLOCK_SIZE, plaintext, AES128_BLOCK_SIZE);
    }
    if (aes128_init(&ctx, key) != 0) {
        return 0;
    }
    aes128_encrypt_blocks_avx2(&ctx, input, output, 8);
    aes128_clear(&ctx);

    for (size_t i = 0; i < 8; ++i) {
        if (memcmp(output + i * AES128_BLOCK_SIZE, expected, AES128_BLOCK_SIZE) != 0) {
            fprintf(stderr, "[AVX2 vector] mismatch in lane %zu\n", i);
            return 0;
        }
    }

    puts("[PASS] AVX2 eight-lane FIPS-197 vector");
    return 1;
}

static int check_cross_implementation(void) {
    enum { MAX_BLOCKS = 39 };
    uint64_t rng = UINT64_C(0x6a09e667f3bcc909);
    uint8_t key[AES128_KEY_SIZE];
    uint8_t input[MAX_BLOCKS * AES128_BLOCK_SIZE];
    uint8_t expected[sizeof(input)];
    uint8_t actual[sizeof(input)];

    for (size_t test = 0; test < 2048; ++test) {
        const size_t blocks = 1U + (size_t)(xorshift64(&rng) % MAX_BLOCKS);
        const size_t bytes = blocks * AES128_BLOCK_SIZE;
        aes128_key_t ctx;

        fill_deterministic(key, sizeof(key), &rng);
        fill_deterministic(input, bytes, &rng);
        if (aes128_init(&ctx, key) != 0) {
            return 0;
        }
        aes128_encrypt_blocks_ref(&ctx, input, expected, blocks);
        aes128_encrypt_blocks_avx2(&ctx, input, actual, blocks);
        aes128_clear(&ctx);

        if (memcmp(expected, actual, bytes) != 0) {
            fprintf(stderr, "[AVX2 cross-check] mismatch at test %zu, blocks=%zu\n", test, blocks);
            return 0;
        }
    }

    puts("[PASS] 2048 variable-length reference/AVX2 cross-checks");
    return 1;
}

static int check_in_place(void) {
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    uint8_t data[25 * AES128_BLOCK_SIZE];
    uint8_t expected[sizeof(data)];
    aes128_key_t ctx;

    for (size_t i = 0; i < sizeof(data); ++i) {
        data[i] = (uint8_t)(i * 23U + 5U);
    }
    if (aes128_init(&ctx, key) != 0) {
        return 0;
    }
    aes128_encrypt_blocks_ref(&ctx, data, expected, 25);
    aes128_encrypt_blocks_avx2(&ctx, data, data, 25);
    aes128_clear(&ctx);

    if (memcmp(data, expected, sizeof(data)) != 0) {
        fputs("[AVX2 in-place] mismatch\n", stderr);
        return 0;
    }

    puts("[PASS] AVX2 in-place encryption with scalar tail");
    return 1;
}

int main(void) {
    if (aes128_avx2_supported()) {
        puts("[INFO] AVX2 detected: hardware gather/shuffle path enabled");
    } else {
        puts("[INFO] AVX2 not detected: correctness test exercises safe T-table fallback");
    }

    int ok = 1;
    ok &= check_eight_standard_blocks();
    ok &= check_cross_implementation();
    ok &= check_in_place();
    if (!ok) {
        return 1;
    }
    puts("All AES-128 AVX2 gather/shuffle tests passed.");
    return 0;
}
