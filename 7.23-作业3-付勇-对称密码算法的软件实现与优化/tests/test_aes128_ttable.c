#include "aes128.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void print_hex(const uint8_t *data, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        fprintf(stderr, "%02x", data[i]);
    }
}

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

static int check_standard_vector(void) {
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

    aes128_key_t ctx;
    uint8_t actual[16];
    if (aes128_init(&ctx, key) != 0) {
        return 0;
    }
    aes128_encrypt_block_ttable(&ctx, plaintext, actual);
    aes128_clear(&ctx);

    if (memcmp(actual, expected, sizeof(actual)) != 0) {
        fputs("[T-table vector] mismatch\n  got:      ", stderr);
        print_hex(actual, sizeof(actual));
        fputs("\n  expected: ", stderr);
        print_hex(expected, sizeof(expected));
        fputc('\n', stderr);
        return 0;
    }

    puts("[PASS] T-table FIPS-197 vector");
    return 1;
}

static int check_cross_implementation(void) {
    uint64_t rng = UINT64_C(0x9e3779b97f4a7c15);
    uint8_t key[16];
    uint8_t input[16 * 8];
    uint8_t ref_output[sizeof(input)];
    uint8_t table_output[sizeof(input)];
    uint8_t recovered[sizeof(input)];

    for (size_t test = 0; test < 4096; ++test) {
        aes128_key_t ctx;
        fill_deterministic(key, sizeof(key), &rng);
        fill_deterministic(input, sizeof(input), &rng);

        if (aes128_init(&ctx, key) != 0) {
            return 0;
        }
        aes128_encrypt_blocks_ref(&ctx, input, ref_output, 8);
        aes128_encrypt_blocks_ttable(&ctx, input, table_output, 8);

        if (memcmp(ref_output, table_output, sizeof(ref_output)) != 0) {
            fprintf(stderr, "[cross-check] mismatch at test %zu\n", test);
            aes128_clear(&ctx);
            return 0;
        }

        aes128_decrypt_blocks_ref(&ctx, table_output, recovered, 8);
        if (memcmp(input, recovered, sizeof(input)) != 0) {
            fprintf(stderr, "[cross-check] roundtrip mismatch at test %zu\n", test);
            aes128_clear(&ctx);
            return 0;
        }
        aes128_clear(&ctx);
    }

    puts("[PASS] 4096 keys x 8 blocks reference/T-table cross-check");
    return 1;
}

static int check_in_place(void) {
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    uint8_t input[16 * 4];
    uint8_t expected[sizeof(input)];
    aes128_key_t ctx;

    for (size_t i = 0; i < sizeof(input); ++i) {
        input[i] = (uint8_t)(i * 17U + 3U);
    }
    if (aes128_init(&ctx, key) != 0) {
        return 0;
    }
    aes128_encrypt_blocks_ref(&ctx, input, expected, 4);
    aes128_encrypt_blocks_ttable(&ctx, input, input, 4);
    aes128_clear(&ctx);

    if (memcmp(input, expected, sizeof(input)) != 0) {
        fputs("[in-place] mismatch\n", stderr);
        return 0;
    }

    puts("[PASS] T-table in-place encryption");
    return 1;
}

int main(void) {
    int ok = 1;
    ok &= check_standard_vector();
    ok &= check_cross_implementation();
    ok &= check_in_place();

    if (!ok) {
        return 1;
    }
    puts("All AES-128 T-table tests passed.");
    return 0;
}
