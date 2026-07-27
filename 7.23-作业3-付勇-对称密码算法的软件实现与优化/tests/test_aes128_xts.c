#include "aes128.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef int (*xts_fn)(
    const aes128_xts_key_t *, const uint8_t *, const uint8_t *, uint8_t *, size_t
);

typedef struct {
    const char *name;
    xts_fn encrypt;
    xts_fn decrypt;
} backend_t;

static const backend_t backends[] = {
    {"reference", aes128_xts_encrypt_ref, aes128_xts_decrypt_ref},
    {"AES-NI scalar", aes128_xts_encrypt_aesni_scalar, aes128_xts_decrypt_aesni_scalar},
    {"AES-NI batch", aes128_xts_encrypt_aesni_batch, aes128_xts_decrypt_aesni_batch},
};

static uint32_t prng_state = UINT32_C(0x6d2b79f5);

static uint32_t next_random(void) {
    uint32_t x = prng_state;
    x ^= x << 13U;
    x ^= x >> 17U;
    x ^= x << 5U;
    prng_state = x;
    return x;
}

static void fill_random(uint8_t *out, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        out[i] = (uint8_t)next_random();
    }
}

static int check_known_answers(void) {
    static const uint8_t key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    static const uint8_t tweak[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const uint8_t expected_32[32] = {
        0xb6,0x24,0x12,0x37,0x1f,0x8d,0x7c,0xf1,
        0xe2,0x7c,0x05,0xaf,0x1a,0x83,0xd9,0xb9,
        0xec,0x41,0x0e,0x71,0xeb,0x45,0x25,0xfb,
        0x59,0x85,0x4e,0x22,0xd5,0x8d,0x3b,0x8f
    };
    static const uint8_t expected_31[31] = {
        0x68,0x93,0xfb,0x98,0x67,0xb3,0x98,0x2b,
        0xf0,0x41,0x50,0x31,0x25,0x3b,0x1c,0xac,
        0xb6,0x24,0x12,0x37,0x1f,0x8d,0x7c,0xf1,
        0xe2,0x7c,0x05,0xaf,0x1a,0x83,0xd9
    };

    uint8_t plaintext[32];
    for (size_t i = 0; i < sizeof(plaintext); ++i) {
        plaintext[i] = (uint8_t)i;
    }

    aes128_xts_key_t ctx;
    if (aes128_xts_init(&ctx, key) != AES128_XTS_OK) {
        fputs("[XTS KAT] key initialization failed\n", stderr);
        return 0;
    }

    uint8_t ciphertext[32];
    uint8_t recovered[32];
    for (size_t b = 0; b < sizeof(backends) / sizeof(backends[0]); ++b) {
        if (backends[b].encrypt(
                &ctx, tweak, plaintext, ciphertext, 32U
            ) != AES128_XTS_OK ||
            memcmp(ciphertext, expected_32, sizeof(expected_32)) != 0) {
            fprintf(stderr, "[XTS KAT full] %s mismatch\n", backends[b].name);
            aes128_xts_clear(&ctx);
            return 0;
        }
        if (backends[b].decrypt(
                &ctx, tweak, ciphertext, recovered, 32U
            ) != AES128_XTS_OK ||
            memcmp(recovered, plaintext, 32U) != 0) {
            fprintf(stderr, "[XTS KAT full decrypt] %s mismatch\n", backends[b].name);
            aes128_xts_clear(&ctx);
            return 0;
        }

        if (backends[b].encrypt(
                &ctx, tweak, plaintext, ciphertext, 31U
            ) != AES128_XTS_OK ||
            memcmp(ciphertext, expected_31, sizeof(expected_31)) != 0) {
            fprintf(stderr, "[XTS KAT CTS] %s mismatch\n", backends[b].name);
            aes128_xts_clear(&ctx);
            return 0;
        }
        if (backends[b].decrypt(
                &ctx, tweak, ciphertext, recovered, 31U
            ) != AES128_XTS_OK ||
            memcmp(recovered, plaintext, 31U) != 0) {
            fprintf(stderr, "[XTS KAT CTS decrypt] %s mismatch\n", backends[b].name);
            aes128_xts_clear(&ctx);
            return 0;
        }
    }

    aes128_xts_clear(&ctx);
    puts("[PASS] OpenSSL-compatible AES-128-XTS full-block and CTS vectors");
    return 1;
}

static int check_random_cross_implementation(void) {
    uint8_t key[32];
    uint8_t tweak[16];
    uint8_t plaintext[2081];
    uint8_t reference[2081];
    uint8_t candidate[2081];
    uint8_t recovered[2081];

    for (size_t trial = 0; trial < 2048U; ++trial) {
        fill_random(key, sizeof(key));
        if (memcmp(key, key + 16U, 16U) == 0) {
            key[31] ^= 1U;
        }
        fill_random(tweak, sizeof(tweak));
        const size_t length = 16U + (size_t)(next_random() % 2066U);
        fill_random(plaintext, length);

        aes128_xts_key_t ctx;
        if (aes128_xts_init(&ctx, key) != AES128_XTS_OK) {
            fprintf(stderr, "[XTS random] init failed at trial %zu\n", trial);
            return 0;
        }
        if (aes128_xts_encrypt_ref(
                &ctx, tweak, plaintext, reference, length
            ) != AES128_XTS_OK) {
            fprintf(stderr, "[XTS random] reference failed at trial %zu\n", trial);
            aes128_xts_clear(&ctx);
            return 0;
        }

        for (size_t b = 1U; b < sizeof(backends) / sizeof(backends[0]); ++b) {
            if (backends[b].encrypt(
                    &ctx, tweak, plaintext, candidate, length
                ) != AES128_XTS_OK ||
                memcmp(candidate, reference, length) != 0) {
                fprintf(stderr, "[XTS random encrypt] %s mismatch at trial %zu length %zu\n",
                        backends[b].name, trial, length);
                aes128_xts_clear(&ctx);
                return 0;
            }
            if (backends[b].decrypt(
                    &ctx, tweak, candidate, recovered, length
                ) != AES128_XTS_OK ||
                memcmp(recovered, plaintext, length) != 0) {
                fprintf(stderr, "[XTS random decrypt] %s mismatch at trial %zu length %zu\n",
                        backends[b].name, trial, length);
                aes128_xts_clear(&ctx);
                return 0;
            }
        }
        aes128_xts_clear(&ctx);
    }

    puts("[PASS] 2048 arbitrary-length XTS cross-checks with ciphertext stealing");
    return 1;
}

static int check_in_place_and_guards(void) {
    static const size_t lengths[] = {16U,17U,31U,32U,33U,127U,128U,129U,1025U};
    uint8_t key[32];
    uint8_t tweak[16];
    uint8_t plaintext[1025];
    uint8_t expected[1025];
    uint8_t buffer[1025];
    fill_random(key, sizeof(key));
    key[31] ^= 0x5aU;
    fill_random(tweak, sizeof(tweak));
    fill_random(plaintext, sizeof(plaintext));

    aes128_xts_key_t ctx;
    if (aes128_xts_init(&ctx, key) != AES128_XTS_OK) {
        return 0;
    }

    for (size_t n = 0; n < sizeof(lengths) / sizeof(lengths[0]); ++n) {
        const size_t length = lengths[n];
        if (aes128_xts_encrypt_ref(
                &ctx, tweak, plaintext, expected, length
            ) != AES128_XTS_OK) {
            aes128_xts_clear(&ctx);
            return 0;
        }
        for (size_t b = 0; b < sizeof(backends) / sizeof(backends[0]); ++b) {
            memcpy(buffer, plaintext, length);
            if (backends[b].encrypt(
                    &ctx, tweak, buffer, buffer, length
                ) != AES128_XTS_OK ||
                memcmp(buffer, expected, length) != 0) {
                fprintf(stderr, "[XTS in-place encrypt] %s length %zu\n",
                        backends[b].name, length);
                aes128_xts_clear(&ctx);
                return 0;
            }
            if (backends[b].decrypt(
                    &ctx, tweak, buffer, buffer, length
                ) != AES128_XTS_OK ||
                memcmp(buffer, plaintext, length) != 0) {
                fprintf(stderr, "[XTS in-place decrypt] %s length %zu\n",
                        backends[b].name, length);
                aes128_xts_clear(&ctx);
                return 0;
            }
        }
    }

    uint8_t weak_key[32];
    memset(weak_key, 0x33, 16U);
    memcpy(weak_key + 16U, weak_key, 16U);
    aes128_xts_key_t weak_ctx;
    if (aes128_xts_init(&weak_ctx, weak_key) != AES128_XTS_WEAK_KEY) {
        fputs("[XTS guard] identical key halves were accepted\n", stderr);
        aes128_xts_clear(&ctx);
        return 0;
    }

    uint8_t tiny[16] = {0};
    if (aes128_xts_encrypt_ref(&ctx, tweak, tiny, tiny, 15U) !=
        AES128_XTS_DATA_UNIT_TOO_SHORT) {
        fputs("[XTS guard] short data unit was accepted\n", stderr);
        aes128_xts_clear(&ctx);
        return 0;
    }

    const size_t too_long = (AES128_XTS_MAX_BLOCKS + 1U) * AES128_BLOCK_SIZE;
    if (aes128_xts_encrypt_ref(&ctx, tweak, tiny, tiny, too_long) !=
        AES128_XTS_LENGTH_LIMIT) {
        fputs("[XTS guard] oversized data unit was accepted\n", stderr);
        aes128_xts_clear(&ctx);
        return 0;
    }

    aes128_xts_clear(&ctx);
    puts("[PASS] XTS in-place encryption/decryption, CTS boundaries and guards");
    return 1;
}

int main(void) {
    printf("[INFO] XTS AES-NI batch path: %s\n",
           aes128_xts_aesni_supported() ? "enabled" : "software fallback");

    int ok = 1;
    ok &= check_known_answers();
    ok &= check_random_cross_implementation();
    ok &= check_in_place_and_guards();
    if (!ok) {
        return 1;
    }
    puts("All AES-128-XTS tests passed.");
    return 0;
}
