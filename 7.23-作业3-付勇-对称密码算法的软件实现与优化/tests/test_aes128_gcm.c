#include "aes128.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef int (*gcm_encrypt_fn)(
    const aes128_key_t *, const uint8_t *, size_t,
    const uint8_t *, size_t, const uint8_t *, uint8_t *, size_t,
    uint8_t *, size_t
);

typedef int (*gcm_decrypt_fn)(
    const aes128_key_t *, const uint8_t *, size_t,
    const uint8_t *, size_t, const uint8_t *, uint8_t *, size_t,
    const uint8_t *, size_t
);

typedef struct {
    const char *name;
    gcm_encrypt_fn encrypt;
    gcm_decrypt_fn decrypt;
} gcm_backend_t;

static const gcm_backend_t backends[] = {
    {"reference", aes128_gcm_encrypt_ref, aes128_gcm_decrypt_ref},
    {"AES-NI + reference GHASH", aes128_gcm_encrypt_aesni, aes128_gcm_decrypt_aesni},
    {"AES-NI + PCLMUL GHASH", aes128_gcm_encrypt_pclmul, aes128_gcm_decrypt_pclmul}
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

static int run_vector(
    const char *label,
    const uint8_t key[16],
    const uint8_t *iv, size_t iv_length,
    const uint8_t *aad, size_t aad_length,
    const uint8_t *plaintext, const uint8_t *ciphertext, size_t length,
    const uint8_t tag[16]
) {
    aes128_key_t ctx;
    uint8_t actual_ciphertext[80];
    uint8_t actual_plaintext[80];
    uint8_t actual_tag[16];

    if (length > sizeof(actual_ciphertext) || aes128_init(&ctx, key) != 0) {
        return 0;
    }

    for (size_t b = 0; b < sizeof(backends) / sizeof(backends[0]); ++b) {
        memset(actual_ciphertext, 0xa5, sizeof(actual_ciphertext));
        memset(actual_tag, 0x5a, sizeof(actual_tag));
        if (backends[b].encrypt(
                &ctx, iv, iv_length, aad, aad_length,
                plaintext, actual_ciphertext, length, actual_tag, 16U
            ) != AES128_GCM_OK ||
            (length != 0U && memcmp(actual_ciphertext, ciphertext, length) != 0) ||
            memcmp(actual_tag, tag, 16U) != 0) {
            fprintf(stderr, "[GCM vector %s] %s encryption mismatch\n", label, backends[b].name);
            aes128_clear(&ctx);
            return 0;
        }

        memset(actual_plaintext, 0x3c, sizeof(actual_plaintext));
        if (backends[b].decrypt(
                &ctx, iv, iv_length, aad, aad_length,
                ciphertext, actual_plaintext, length, tag, 16U
            ) != AES128_GCM_OK ||
            (length != 0U && memcmp(actual_plaintext, plaintext, length) != 0)) {
            fprintf(stderr, "[GCM vector %s] %s decryption mismatch\n", label, backends[b].name);
            aes128_clear(&ctx);
            return 0;
        }
    }

    aes128_clear(&ctx);
    return 1;
}

static int check_nist_vectors(void) {
    static const uint8_t zero_key[16] = {0};
    static const uint8_t zero_iv[12] = {0};
    static const uint8_t empty_tag[16] = {
        0x58,0xe2,0xfc,0xce,0xfa,0x7e,0x30,0x61,
        0x36,0x7f,0x1d,0x57,0xa4,0xe7,0x45,0x5a
    };
    static const uint8_t zero_plaintext[16] = {0};
    static const uint8_t zero_ciphertext[16] = {
        0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,
        0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78
    };
    static const uint8_t zero_tag[16] = {
        0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,
        0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf
    };
    static const uint8_t key[16] = {
        0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
        0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08
    };
    static const uint8_t iv96[12] = {
        0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88
    };
    static const uint8_t iv64[8] = {
        0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad
    };
    static const uint8_t aad[20] = {
        0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
        0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,
        0xab,0xad,0xda,0xd2
    };
    static const uint8_t plaintext[60] = {
        0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
        0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
        0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,
        0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57,0xba,0x63,0x7b,0x39
    };
    static const uint8_t ciphertext96[60] = {
        0x42,0x83,0x1e,0xc2,0x21,0x77,0x74,0x24,0x4b,0x72,0x21,0xb7,0x84,0xd0,0xd4,0x9c,
        0xe3,0xaa,0x21,0x2f,0x2c,0x02,0xa4,0xe0,0x35,0xc1,0x7e,0x23,0x29,0xac,0xa1,0x2e,
        0x21,0xd5,0x14,0xb2,0x54,0x66,0x93,0x1c,0x7d,0x8f,0x6a,0x5a,0xac,0x84,0xaa,0x05,
        0x1b,0xa3,0x0b,0x39,0x6a,0x0a,0xac,0x97,0x3d,0x58,0xe0,0x91
    };
    static const uint8_t tag96[16] = {
        0x5b,0xc9,0x4f,0xbc,0x32,0x21,0xa5,0xdb,
        0x94,0xfa,0xe9,0x5a,0xe7,0x12,0x1a,0x47
    };
    static const uint8_t ciphertext64[60] = {
        0x61,0x35,0x3b,0x4c,0x28,0x06,0x93,0x4a,0x77,0x7f,0xf5,0x1f,0xa2,0x2a,0x47,0x55,
        0x69,0x9b,0x2a,0x71,0x4f,0xcd,0xc6,0xf8,0x37,0x66,0xe5,0xf9,0x7b,0x6c,0x74,0x23,
        0x73,0x80,0x69,0x00,0xe4,0x9f,0x24,0xb2,0x2b,0x09,0x75,0x44,0xd4,0x89,0x6b,0x42,
        0x49,0x89,0xb5,0xe1,0xeb,0xac,0x0f,0x07,0xc2,0x3f,0x45,0x98
    };
    static const uint8_t tag64[16] = {
        0x36,0x12,0xd2,0xe7,0x9e,0x3b,0x07,0x85,
        0x56,0x1b,0xe1,0x4a,0xac,0xa2,0xfc,0xcb
    };

    if (!run_vector("empty", zero_key, zero_iv, sizeof(zero_iv), NULL, 0U,
                    NULL, NULL, 0U, empty_tag) ||
        !run_vector("one block", zero_key, zero_iv, sizeof(zero_iv), NULL, 0U,
                    zero_plaintext, zero_ciphertext, sizeof(zero_plaintext), zero_tag) ||
        !run_vector("96-bit IV + AAD", key, iv96, sizeof(iv96), aad, sizeof(aad),
                    plaintext, ciphertext96, sizeof(plaintext), tag96) ||
        !run_vector("64-bit IV + AAD", key, iv64, sizeof(iv64), aad, sizeof(aad),
                    plaintext, ciphertext64, sizeof(plaintext), tag64)) {
        return 0;
    }

    puts("[PASS] NIST SP 800-38D AES-128-GCM vectors (96-bit and non-96-bit IVs)");
    return 1;
}

static int check_random_cross_implementation(void) {
    enum { MAX_TEXT = 1025, MAX_AAD = 129, MAX_IV = 31 };
    uint64_t rng = UINT64_C(0x243f6a8885a308d3);
    uint8_t key[16];
    uint8_t iv[MAX_IV];
    uint8_t aad[MAX_AAD];
    uint8_t plaintext[MAX_TEXT];
    uint8_t expected[MAX_TEXT];
    uint8_t actual[MAX_TEXT];
    uint8_t recovered[MAX_TEXT];
    uint8_t expected_tag[16];
    uint8_t actual_tag[16];

    for (size_t test = 0; test < 1024U; ++test) {
        const size_t length = (size_t)(xorshift64(&rng) % (MAX_TEXT + 1U));
        const size_t aad_length = (size_t)(xorshift64(&rng) % (MAX_AAD + 1U));
        size_t iv_length = 1U + (size_t)(xorshift64(&rng) % MAX_IV);
        if ((test & 3U) == 0U) {
            iv_length = 12U;
        }
        static const size_t tag_lengths[] = {4U, 8U, 12U, 13U, 14U, 15U, 16U};
        const size_t tag_length = tag_lengths[
            (size_t)(xorshift64(&rng) % (sizeof(tag_lengths) / sizeof(tag_lengths[0])))
        ];
        aes128_key_t ctx;

        fill_deterministic(key, sizeof(key), &rng);
        fill_deterministic(iv, iv_length, &rng);
        fill_deterministic(aad, aad_length, &rng);
        fill_deterministic(plaintext, length, &rng);
        if (aes128_init(&ctx, key) != 0) {
            return 0;
        }

        if (aes128_gcm_encrypt_ref(
                &ctx, iv, iv_length, aad, aad_length,
                plaintext, expected, length, expected_tag, tag_length
            ) != AES128_GCM_OK) {
            aes128_clear(&ctx);
            return 0;
        }

        for (size_t b = 1U; b < sizeof(backends) / sizeof(backends[0]); ++b) {
            if (backends[b].encrypt(
                    &ctx, iv, iv_length, aad, aad_length,
                    plaintext, actual, length, actual_tag, tag_length
                ) != AES128_GCM_OK ||
                memcmp(actual, expected, length) != 0 ||
                memcmp(actual_tag, expected_tag, tag_length) != 0) {
                fprintf(stderr, "[GCM cross-check] %s mismatch at test %zu\n", backends[b].name, test);
                aes128_clear(&ctx);
                return 0;
            }

            if (backends[b].decrypt(
                    &ctx, iv, iv_length, aad, aad_length,
                    actual, recovered, length, actual_tag, tag_length
                ) != AES128_GCM_OK || memcmp(recovered, plaintext, length) != 0) {
                fprintf(stderr, "[GCM roundtrip] %s mismatch at test %zu\n", backends[b].name, test);
                aes128_clear(&ctx);
                return 0;
            }
        }
        aes128_clear(&ctx);
    }

    puts("[PASS] 1024 arbitrary-length GCM cross-checks with AAD, IV and truncated tags");
    return 1;
}

static int check_authentication_and_in_place(void) {
    static const uint8_t key[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const uint8_t iv[12] = {
        0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab
    };
    static const uint8_t aad[] = "authenticated metadata";
    enum { LENGTH = 8 * 16 + 13 };
    uint8_t original[LENGTH];
    uint8_t buffer[LENGTH];
    uint8_t ciphertext[LENGTH];
    uint8_t tag[16];
    uint8_t bad_tag[16];
    aes128_key_t ctx;

    for (size_t i = 0; i < sizeof(original); ++i) {
        original[i] = (uint8_t)(i * 31U + 9U);
    }
    if (aes128_init(&ctx, key) != 0) {
        return 0;
    }

    for (size_t b = 0; b < sizeof(backends) / sizeof(backends[0]); ++b) {
        memcpy(buffer, original, sizeof(buffer));
        if (backends[b].encrypt(
                &ctx, iv, sizeof(iv), aad, sizeof(aad),
                buffer, buffer, sizeof(buffer), tag, sizeof(tag)
            ) != AES128_GCM_OK) {
            aes128_clear(&ctx);
            return 0;
        }
        memcpy(ciphertext, buffer, sizeof(ciphertext));

        if (backends[b].decrypt(
                &ctx, iv, sizeof(iv), aad, sizeof(aad),
                buffer, buffer, sizeof(buffer), tag, sizeof(tag)
            ) != AES128_GCM_OK || memcmp(buffer, original, sizeof(buffer)) != 0) {
            fprintf(stderr, "[GCM in-place] %s mismatch\n", backends[b].name);
            aes128_clear(&ctx);
            return 0;
        }

        memcpy(bad_tag, tag, sizeof(tag));
        bad_tag[7] ^= 0x80U;
        memset(buffer, 0x5c, sizeof(buffer));
        if (backends[b].decrypt(
                &ctx, iv, sizeof(iv), aad, sizeof(aad),
                ciphertext, buffer, sizeof(buffer), bad_tag, sizeof(bad_tag)
            ) != AES128_GCM_TAG_MISMATCH) {
            fprintf(stderr, "[GCM bad tag] %s accepted a forged tag\n", backends[b].name);
            aes128_clear(&ctx);
            return 0;
        }
        for (size_t i = 0; i < sizeof(buffer); ++i) {
            if (buffer[i] != 0x5cU) {
                fprintf(stderr, "[GCM bad tag] %s modified plaintext before authentication\n", backends[b].name);
                aes128_clear(&ctx);
                return 0;
            }
        }

        ciphertext[3] ^= 1U;
        memset(buffer, 0x6d, sizeof(buffer));
        if (backends[b].decrypt(
                &ctx, iv, sizeof(iv), aad, sizeof(aad),
                ciphertext, buffer, sizeof(buffer), tag, sizeof(tag)
            ) != AES128_GCM_TAG_MISMATCH) {
            fprintf(stderr, "[GCM tamper] %s accepted modified ciphertext\n", backends[b].name);
            aes128_clear(&ctx);
            return 0;
        }
        ciphertext[3] ^= 1U;

        uint8_t bad_aad[sizeof(aad)];
        memcpy(bad_aad, aad, sizeof(bad_aad));
        bad_aad[2] ^= 1U;
        memset(buffer, 0x7e, sizeof(buffer));
        if (backends[b].decrypt(
                &ctx, iv, sizeof(iv), bad_aad, sizeof(bad_aad),
                ciphertext, buffer, sizeof(buffer), tag, sizeof(tag)
            ) != AES128_GCM_TAG_MISMATCH) {
            fprintf(stderr, "[GCM tamper] %s accepted modified AAD\n", backends[b].name);
            aes128_clear(&ctx);
            return 0;
        }
    }

    aes128_clear(&ctx);
    puts("[PASS] GCM in-place operation, constant-time tag check and tamper rejection");
    return 1;
}

int main(void) {
    printf("[INFO] GCM PCLMULQDQ path: %s\n",
           aes128_gcm_pclmul_supported() ? "enabled" : "software fallback");

    int ok = 1;
    ok &= check_nist_vectors();
    ok &= check_random_cross_implementation();
    ok &= check_authentication_and_in_place();
    if (!ok) {
        return 1;
    }
    puts("All AES-128-GCM tests passed.");
    return 0;
}
