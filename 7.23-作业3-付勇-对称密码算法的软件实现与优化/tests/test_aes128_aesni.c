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

    uint8_t encrypted[16];
    uint8_t decrypted[16];
    aes128_key_t ctx;
    if (aes128_init(&ctx, key) != 0) {
        return 0;
    }
    aes128_encrypt_block_aesni(&ctx, plaintext, encrypted);
    aes128_decrypt_block_aesni(&ctx, encrypted, decrypted);
    aes128_clear(&ctx);

    if (memcmp(encrypted, expected, sizeof(expected)) != 0) {
        fputs("[AES-NI vector] encryption mismatch\n", stderr);
        return 0;
    }
    if (memcmp(decrypted, plaintext, sizeof(plaintext)) != 0) {
        fputs("[AES-NI vector] decryption mismatch\n", stderr);
        return 0;
    }
    puts("[PASS] AES-NI FIPS-197 encrypt/decrypt vector");
    return 1;
}

static int check_cross_implementation(void) {
    enum { MAX_BLOCKS = 47 };
    uint64_t rng = UINT64_C(0xbb67ae8584caa73b);
    uint8_t key[AES128_KEY_SIZE];
    uint8_t input[MAX_BLOCKS * AES128_BLOCK_SIZE];
    uint8_t expected[MAX_BLOCKS * AES128_BLOCK_SIZE];
    uint8_t actual[MAX_BLOCKS * AES128_BLOCK_SIZE];
    uint8_t recovered[MAX_BLOCKS * AES128_BLOCK_SIZE];

    for (size_t test = 0; test < 4096; ++test) {
        const size_t blocks = 1U + (size_t)(xorshift64(&rng) % MAX_BLOCKS);
        const size_t bytes = blocks * AES128_BLOCK_SIZE;
        aes128_key_t ctx;

        fill_deterministic(key, sizeof(key), &rng);
        fill_deterministic(input, bytes, &rng);
        if (aes128_init(&ctx, key) != 0) {
            return 0;
        }
        aes128_encrypt_blocks_ref(&ctx, input, expected, blocks);
        aes128_encrypt_blocks_aesni(&ctx, input, actual, blocks);
        aes128_decrypt_blocks_aesni(&ctx, actual, recovered, blocks);
        aes128_clear(&ctx);

        if (memcmp(expected, actual, bytes) != 0) {
            fprintf(stderr, "[AES-NI cross-check] encryption mismatch at test %zu, blocks=%zu\n", test, blocks);
            return 0;
        }
        if (memcmp(input, recovered, bytes) != 0) {
            fprintf(stderr, "[AES-NI cross-check] decryption mismatch at test %zu, blocks=%zu\n", test, blocks);
            return 0;
        }
    }

    puts("[PASS] 4096 variable-length AES-NI encrypt/decrypt cross-checks");
    return 1;
}

static int check_in_place(void) {
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    uint8_t original[29 * AES128_BLOCK_SIZE];
    uint8_t data[sizeof(original)];
    uint8_t expected[sizeof(original)];
    aes128_key_t ctx;

    for (size_t i = 0; i < sizeof(original); ++i) {
        original[i] = (uint8_t)(i * 41U + 11U);
    }
    memcpy(data, original, sizeof(data));
    if (aes128_init(&ctx, key) != 0) {
        return 0;
    }
    aes128_encrypt_blocks_ref(&ctx, original, expected, 29);
    aes128_encrypt_blocks_aesni(&ctx, data, data, 29);
    if (memcmp(data, expected, sizeof(data)) != 0) {
        aes128_clear(&ctx);
        fputs("[AES-NI in-place] encryption mismatch\n", stderr);
        return 0;
    }
    aes128_decrypt_blocks_aesni(&ctx, data, data, 29);
    aes128_clear(&ctx);

    if (memcmp(data, original, sizeof(data)) != 0) {
        fputs("[AES-NI in-place] decryption mismatch\n", stderr);
        return 0;
    }
    puts("[PASS] AES-NI in-place encryption/decryption with 8/4/1-block paths");
    return 1;
}

int main(void) {
    if (aes128_aesni_supported()) {
        puts("[INFO] AES-NI detected: hardware AES round instructions enabled");
    } else {
        puts("[INFO] AES-NI not detected: correctness test exercises safe software fallback");
    }

    int ok = 1;
    ok &= check_standard_vector();
    ok &= check_cross_implementation();
    ok &= check_in_place();
    if (!ok) {
        return 1;
    }
    puts("All AES-128 AES-NI tests passed.");
    return 0;
}
