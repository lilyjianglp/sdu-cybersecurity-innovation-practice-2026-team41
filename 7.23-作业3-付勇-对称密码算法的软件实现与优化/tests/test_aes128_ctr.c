#include "aes128.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef int (*ctr_fn)(
    const aes128_key_t *, uint8_t[AES128_BLOCK_SIZE],
    const uint8_t *, uint8_t *, size_t
);

typedef struct {
    const char *name;
    ctr_fn crypt;
} ctr_backend_t;

static const ctr_backend_t backends[] = {
    {"reference", aes128_ctr_crypt_ref},
    {"T-table", aes128_ctr_crypt_ttable},
    {"AVX2", aes128_ctr_crypt_avx2},
    {"AES-NI", aes128_ctr_crypt_aesni}
};

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

static int check_nist_vector(void) {
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    static const uint8_t initial_counter[16] = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
        0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
    };
    static const uint8_t final_counter[16] = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
        0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xff,0x03
    };
    static const uint8_t plaintext[64] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
        0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
        0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
        0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10
    };
    static const uint8_t ciphertext[64] = {
        0x87,0x4d,0x61,0x91,0xb6,0x20,0xe3,0x26,0x1b,0xef,0x68,0x64,0x99,0x0d,0xb6,0xce,
        0x98,0x06,0xf6,0x6b,0x79,0x70,0xfd,0xff,0x86,0x17,0x18,0x7b,0xb9,0xff,0xfd,0xff,
        0x5a,0xe4,0xdf,0x3e,0xdb,0xd5,0xd3,0x5e,0x5b,0x4f,0x09,0x02,0x0d,0xb0,0x3e,0xab,
        0x1e,0x03,0x1d,0xda,0x2f,0xbe,0x03,0xd1,0x79,0x21,0x70,0xa0,0xf3,0x00,0x9c,0xee
    };

    aes128_key_t ctx;
    if (aes128_init(&ctx, key) != 0) {
        return 0;
    }

    for (size_t b = 0; b < sizeof(backends) / sizeof(backends[0]); ++b) {
        uint8_t counter[16];
        uint8_t output[64];
        uint8_t recovered[64];
        memcpy(counter, initial_counter, sizeof(counter));
        if (backends[b].crypt(&ctx, counter, plaintext, output, sizeof(output)) != AES128_CTR_OK ||
            memcmp(output, ciphertext, sizeof(output)) != 0 ||
            memcmp(counter, final_counter, sizeof(counter)) != 0) {
            fprintf(stderr, "[CTR NIST] %s encryption mismatch\n", backends[b].name);
            aes128_clear(&ctx);
            return 0;
        }

        memcpy(counter, initial_counter, sizeof(counter));
        if (backends[b].crypt(&ctx, counter, ciphertext, recovered, sizeof(recovered)) != AES128_CTR_OK ||
            memcmp(recovered, plaintext, sizeof(recovered)) != 0 ||
            memcmp(counter, final_counter, sizeof(counter)) != 0) {
            fprintf(stderr, "[CTR NIST] %s decryption mismatch\n", backends[b].name);
            aes128_clear(&ctx);
            return 0;
        }
    }

    aes128_clear(&ctx);
    puts("[PASS] NIST SP 800-38A AES-128-CTR vector on all backends");
    return 1;
}

static int check_random_cross_implementation(void) {
    enum { MAX_BYTES = 1537 };
    uint64_t rng = UINT64_C(0x3c6ef372fe94f82b);
    uint8_t key[16];
    uint8_t initial_counter[16];
    uint8_t input[MAX_BYTES];
    uint8_t expected[MAX_BYTES];
    uint8_t actual[MAX_BYTES];
    uint8_t recovered[MAX_BYTES];

    for (size_t test = 0; test < 2048U; ++test) {
        const size_t length = (size_t)(xorshift64(&rng) % (MAX_BYTES + 1U));
        uint8_t expected_counter[16];
        aes128_key_t ctx;

        fill_deterministic(key, sizeof(key), &rng);
        fill_deterministic(initial_counter, sizeof(initial_counter), &rng);
        /* Keep well away from 2^128 exhaustion for this randomized test. */
        initial_counter[0] &= 0x7fU;
        fill_deterministic(input, length, &rng);
        if (aes128_init(&ctx, key) != 0) {
            return 0;
        }

        memcpy(expected_counter, initial_counter, sizeof(expected_counter));
        if (aes128_ctr_crypt_ref(
                &ctx, expected_counter, input, expected, length
            ) != AES128_CTR_OK) {
            aes128_clear(&ctx);
            return 0;
        }

        for (size_t b = 1U; b < sizeof(backends) / sizeof(backends[0]); ++b) {
            uint8_t counter[16];
            memcpy(counter, initial_counter, sizeof(counter));
            if (backends[b].crypt(&ctx, counter, input, actual, length) != AES128_CTR_OK ||
                memcmp(actual, expected, length) != 0 ||
                memcmp(counter, expected_counter, sizeof(counter)) != 0) {
                fprintf(stderr,
                        "[CTR cross-check] %s mismatch at test %zu, length=%zu\n",
                        backends[b].name, test, length);
                aes128_clear(&ctx);
                return 0;
            }

            memcpy(counter, initial_counter, sizeof(counter));
            if (backends[b].crypt(&ctx, counter, actual, recovered, length) != AES128_CTR_OK ||
                memcmp(recovered, input, length) != 0) {
                fprintf(stderr,
                        "[CTR roundtrip] %s mismatch at test %zu, length=%zu\n",
                        backends[b].name, test, length);
                aes128_clear(&ctx);
                return 0;
            }
        }
        aes128_clear(&ctx);
    }

    puts("[PASS] 2048 arbitrary-length CTR cross-checks (including partial blocks)");
    return 1;
}

static int check_in_place_and_carry(void) {
    static const uint8_t key[16] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81
    };
    static const uint8_t initial_counter[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xff,0xff,0xff,0xfc
    };
    static const uint8_t expected_counter[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbc,0x00,0x00,0x00,0x05
    };
    enum { LENGTH = 8 * AES128_BLOCK_SIZE + 13 };
    uint8_t original[LENGTH];
    uint8_t expected[LENGTH];
    aes128_key_t ctx;

    for (size_t i = 0; i < sizeof(original); ++i) {
        original[i] = (uint8_t)(i * 37U + 19U);
    }
    if (aes128_init(&ctx, key) != 0) {
        return 0;
    }

    uint8_t ref_counter[16];
    memcpy(ref_counter, initial_counter, sizeof(ref_counter));
    if (aes128_ctr_crypt_ref(
            &ctx, ref_counter, original, expected, sizeof(expected)
        ) != AES128_CTR_OK ||
        memcmp(ref_counter, expected_counter, sizeof(ref_counter)) != 0) {
        aes128_clear(&ctx);
        fputs("[CTR carry] reference counter mismatch\n", stderr);
        return 0;
    }

    for (size_t b = 0; b < sizeof(backends) / sizeof(backends[0]); ++b) {
        uint8_t counter[16];
        uint8_t data[LENGTH];
        memcpy(counter, initial_counter, sizeof(counter));
        memcpy(data, original, sizeof(data));
        if (backends[b].crypt(&ctx, counter, data, data, sizeof(data)) != AES128_CTR_OK ||
            memcmp(data, expected, sizeof(data)) != 0 ||
            memcmp(counter, expected_counter, sizeof(counter)) != 0) {
            fprintf(stderr, "[CTR in-place/carry] %s mismatch\n", backends[b].name);
            aes128_clear(&ctx);
            return 0;
        }
    }

    aes128_clear(&ctx);
    puts("[PASS] CTR in-place operation and low-32-bit counter carry");
    return 1;
}

static int check_exhaustion_and_zero_length(void) {
    static const uint8_t key[16] = {0};
    uint8_t exhausted[16];
    uint8_t counter[16];
    uint8_t input = 0x5a;
    uint8_t output = 0xa5;
    aes128_key_t ctx;

    memset(exhausted, 0xff, sizeof(exhausted));
    if (aes128_init(&ctx, key) != 0) {
        return 0;
    }

    for (size_t b = 0; b < sizeof(backends) / sizeof(backends[0]); ++b) {
        memcpy(counter, exhausted, sizeof(counter));
        output = 0xa5;
        if (backends[b].crypt(&ctx, counter, &input, &output, 1U) != AES128_CTR_COUNTER_EXHAUSTED ||
            memcmp(counter, exhausted, sizeof(counter)) != 0 || output != 0xa5) {
            fprintf(stderr, "[CTR exhaustion] %s did not reject wrap safely\n", backends[b].name);
            aes128_clear(&ctx);
            return 0;
        }

        memset(counter, 0x42, sizeof(counter));
        uint8_t unchanged[16];
        memcpy(unchanged, counter, sizeof(unchanged));
        if (backends[b].crypt(&ctx, counter, NULL, NULL, 0U) != AES128_CTR_OK ||
            memcmp(counter, unchanged, sizeof(counter)) != 0) {
            fprintf(stderr, "[CTR zero length] %s mismatch\n", backends[b].name);
            aes128_clear(&ctx);
            return 0;
        }
    }

    aes128_clear(&ctx);
    puts("[PASS] CTR counter-exhaustion guard and zero-length handling");
    return 1;
}

int main(void) {
    printf("[INFO] CTR AES-NI batch path: %s\n",
           aes128_ctr_aesni_supported() ? "enabled" : "software fallback");

    int ok = 1;
    ok &= check_nist_vector();
    ok &= check_random_cross_implementation();
    ok &= check_in_place_and_carry();
    ok &= check_exhaustion_and_zero_length();
    if (!ok) {
        return 1;
    }
    puts("All AES-128-CTR tests passed.");
    return 0;
}
