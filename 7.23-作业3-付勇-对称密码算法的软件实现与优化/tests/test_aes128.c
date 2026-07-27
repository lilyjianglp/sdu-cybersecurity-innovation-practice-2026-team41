#include "aes128.h"

#include <stdio.h>
#include <string.h>

static int check_vector(
    const char *name,
    const uint8_t key[16],
    const uint8_t plaintext[16],
    const uint8_t expected[16]
) {
    aes128_key_t ctx;
    uint8_t ciphertext[16];
    uint8_t recovered[16];

    if (aes128_init(&ctx, key) != 0) {
        fprintf(stderr, "[%s] key initialization failed\n", name);
        return 0;
    }

    aes128_encrypt_block_ref(&ctx, plaintext, ciphertext);
    if (memcmp(ciphertext, expected, sizeof(ciphertext)) != 0) {
        fprintf(stderr, "[%s] encryption mismatch\n", name);
        fprintf(stderr, "  got:      ");
        for (size_t i = 0; i < sizeof(ciphertext); ++i) {
            fprintf(stderr, "%02x", ciphertext[i]);
        }
        fprintf(stderr, "\n  expected: ");
        for (size_t i = 0; i < sizeof(ciphertext); ++i) {
            fprintf(stderr, "%02x", expected[i]);
        }
        fprintf(stderr, "\n");
        aes128_clear(&ctx);
        return 0;
    }

    aes128_decrypt_block_ref(&ctx, ciphertext, recovered);
    if (memcmp(recovered, plaintext, sizeof(recovered)) != 0) {
        fprintf(stderr, "[%s] decryption mismatch\n", name);
        aes128_clear(&ctx);
        return 0;
    }

    aes128_clear(&ctx);
    printf("[PASS] %s\n", name);
    return 1;
}

static int check_multiblock_roundtrip(void) {
    aes128_key_t ctx;
    uint8_t key[16];
    uint8_t input[16 * 8];
    uint8_t encrypted[sizeof(input)];
    uint8_t recovered[sizeof(input)];

    for (size_t i = 0; i < sizeof(key); ++i) {
        key[i] = (uint8_t)(0xa0U + i);
    }
    for (size_t i = 0; i < sizeof(input); ++i) {
        input[i] = (uint8_t)(i * 37U + 11U);
    }

    if (aes128_init(&ctx, key) != 0) {
        return 0;
    }
    aes128_encrypt_blocks_ref(&ctx, input, encrypted, 8);
    aes128_decrypt_blocks_ref(&ctx, encrypted, recovered, 8);
    aes128_clear(&ctx);

    if (memcmp(input, recovered, sizeof(input)) != 0) {
        fprintf(stderr, "[multiblock] roundtrip mismatch\n");
        return 0;
    }

    printf("[PASS] 8-block roundtrip\n");
    return 1;
}

int main(void) {
    static const uint8_t key1[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const uint8_t plain1[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    static const uint8_t cipher1[16] = {
        0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
        0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a
    };

    static const uint8_t key2[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    static const uint8_t plain2[16] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };
    static const uint8_t cipher2[16] = {
        0x3a,0xd7,0x7b,0xb4,0x0d,0x7a,0x36,0x60,
        0xa8,0x9e,0xca,0xf3,0x24,0x66,0xef,0x97
    };

    int ok = 1;
    ok &= check_vector("FIPS-197 AES-128", key1, plain1, cipher1);
    ok &= check_vector("SP 800-38A AES-128", key2, plain2, cipher2);
    ok &= check_multiblock_roundtrip();

    if (!ok) {
        return 1;
    }

    puts("All AES-128 reference tests passed.");
    return 0;
}
