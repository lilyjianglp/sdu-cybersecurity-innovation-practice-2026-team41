#include "aes128.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
#include <emmintrin.h>
#endif

typedef void (*xts_blocks_fn)(
    const aes128_key_t *, const uint8_t *, uint8_t *, size_t
);

typedef enum {
    XTS_ENCRYPT = 0,
    XTS_DECRYPT = 1
} xts_direction_t;

static int xts_validate(
    const aes128_xts_key_t *ctx,
    const uint8_t tweak[AES128_BLOCK_SIZE],
    const uint8_t *in,
    uint8_t *out,
    size_t length
) {
    if (ctx == NULL || tweak == NULL) {
        return AES128_XTS_INVALID_ARGUMENT;
    }
    if (length < AES128_BLOCK_SIZE) {
        return AES128_XTS_DATA_UNIT_TOO_SHORT;
    }
    if (in == NULL || out == NULL) {
        return AES128_XTS_INVALID_ARGUMENT;
    }

    const size_t blocks = length / AES128_BLOCK_SIZE +
        (length % AES128_BLOCK_SIZE != 0U ? 1U : 0U);
    if (blocks > AES128_XTS_MAX_BLOCKS) {
        return AES128_XTS_LENGTH_LIMIT;
    }
    return AES128_XTS_OK;
}

static void xor_block(
    const uint8_t lhs[AES128_BLOCK_SIZE],
    const uint8_t rhs[AES128_BLOCK_SIZE],
    uint8_t out[AES128_BLOCK_SIZE]
) {
    for (size_t i = 0; i < AES128_BLOCK_SIZE; ++i) {
        out[i] = (uint8_t)(lhs[i] ^ rhs[i]);
    }
}

/* XTS represents field elements in little-endian byte order. Multiplication
 * by alpha shifts toward higher byte indices and reduces with x^128 + x^7 +
 * x^2 + x + 1, represented by 0x87 in byte zero. */
static void xts_mul_alpha(uint8_t tweak[AES128_BLOCK_SIZE]) {
    uint8_t carry = 0U;
    for (size_t i = 0; i < AES128_BLOCK_SIZE; ++i) {
        const uint8_t next = (uint8_t)(tweak[i] >> 7U);
        tweak[i] = (uint8_t)((uint8_t)(tweak[i] << 1U) | carry);
        carry = next;
    }
    if (carry != 0U) {
        tweak[0] ^= UINT8_C(0x87);
    }
}

static void xex_one(
    const aes128_key_t *data_key,
    xts_blocks_fn crypt,
    const uint8_t tweak[AES128_BLOCK_SIZE],
    const uint8_t in[AES128_BLOCK_SIZE],
    uint8_t out[AES128_BLOCK_SIZE]
) {
    uint8_t temporary[AES128_BLOCK_SIZE];
    xor_block(in, tweak, temporary);
    crypt(data_key, temporary, temporary, 1U);
    xor_block(temporary, tweak, out);
    memset(temporary, 0, sizeof(temporary));
}

static void process_scalar_blocks(
    const aes128_key_t *data_key,
    xts_blocks_fn crypt,
    uint8_t tweak[AES128_BLOCK_SIZE],
    const uint8_t *in,
    uint8_t *out,
    size_t blocks
) {
    for (size_t block = 0; block < blocks; ++block) {
        xex_one(data_key, crypt, tweak, in, out);
        xts_mul_alpha(tweak);
        in += AES128_BLOCK_SIZE;
        out += AES128_BLOCK_SIZE;
    }
}

#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
__attribute__((target("sse2")))
static void xor_batch_x86(
    const uint8_t *in,
    const uint8_t *tweaks,
    uint8_t *out,
    size_t blocks
) {
    for (size_t block = 0; block < blocks; ++block) {
        const size_t offset = block * AES128_BLOCK_SIZE;
        const __m128i value = _mm_loadu_si128(
            (const __m128i *)(const void *)(in + offset)
        );
        const __m128i tw = _mm_loadu_si128(
            (const __m128i *)(const void *)(tweaks + offset)
        );
        _mm_storeu_si128(
            (__m128i *)(void *)(out + offset), _mm_xor_si128(value, tw)
        );
    }
}
#endif

#if !((defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__)))
static void xor_batch_portable(
    const uint8_t *in,
    const uint8_t *tweaks,
    uint8_t *out,
    size_t blocks
) {
    for (size_t block = 0; block < blocks; ++block) {
        xor_block(
            in + block * AES128_BLOCK_SIZE,
            tweaks + block * AES128_BLOCK_SIZE,
            out + block * AES128_BLOCK_SIZE
        );
    }
}
#endif

static void xor_batch(
    const uint8_t *in,
    const uint8_t *tweaks,
    uint8_t *out,
    size_t blocks
) {
#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
    xor_batch_x86(in, tweaks, out, blocks);
#else
    xor_batch_portable(in, tweaks, out, blocks);
#endif
}

static void make_tweak_batch(
    uint8_t current[AES128_BLOCK_SIZE],
    uint8_t *tweaks,
    size_t blocks
) {
    for (size_t block = 0; block < blocks; ++block) {
        memcpy(tweaks + block * AES128_BLOCK_SIZE, current, AES128_BLOCK_SIZE);
        xts_mul_alpha(current);
    }
}

static void process_batched_blocks(
    const aes128_key_t *data_key,
    xts_blocks_fn crypt,
    uint8_t tweak[AES128_BLOCK_SIZE],
    const uint8_t *in,
    uint8_t *out,
    size_t blocks
) {
    uint8_t tweaks[8U * AES128_BLOCK_SIZE];
    uint8_t temporary[8U * AES128_BLOCK_SIZE];

    while (blocks >= 8U) {
        make_tweak_batch(tweak, tweaks, 8U);
        xor_batch(in, tweaks, temporary, 8U);
        crypt(data_key, temporary, temporary, 8U);
        xor_batch(temporary, tweaks, out, 8U);
        in += 8U * AES128_BLOCK_SIZE;
        out += 8U * AES128_BLOCK_SIZE;
        blocks -= 8U;
    }

    if (blocks >= 4U) {
        make_tweak_batch(tweak, tweaks, 4U);
        xor_batch(in, tweaks, temporary, 4U);
        crypt(data_key, temporary, temporary, 4U);
        xor_batch(temporary, tweaks, out, 4U);
        in += 4U * AES128_BLOCK_SIZE;
        out += 4U * AES128_BLOCK_SIZE;
        blocks -= 4U;
    }

    if (blocks != 0U) {
        process_scalar_blocks(data_key, crypt, tweak, in, out, blocks);
    }

    memset(tweaks, 0, sizeof(tweaks));
    memset(temporary, 0, sizeof(temporary));
}

static int xts_crypt(
    const aes128_xts_key_t *ctx,
    const uint8_t tweak_input[AES128_BLOCK_SIZE],
    const uint8_t *in,
    uint8_t *out,
    size_t length,
    xts_direction_t direction,
    int batched,
    int use_aesni
) {
    const int status = xts_validate(ctx, tweak_input, in, out, length);
    if (status != AES128_XTS_OK) {
        return status;
    }

    xts_blocks_fn tweak_encrypt = use_aesni
        ? aes128_encrypt_blocks_aesni : aes128_encrypt_blocks_ref;
    xts_blocks_fn data_crypt;
    if (direction == XTS_ENCRYPT) {
        data_crypt = use_aesni
            ? aes128_encrypt_blocks_aesni : aes128_encrypt_blocks_ref;
    } else {
        data_crypt = use_aesni
            ? aes128_decrypt_blocks_aesni : aes128_decrypt_blocks_ref;
    }

    uint8_t tweak[AES128_BLOCK_SIZE];
    tweak_encrypt(&ctx->tweak_key, tweak_input, tweak, 1U);

    const size_t full_blocks = length / AES128_BLOCK_SIZE;
    const size_t partial = length % AES128_BLOCK_SIZE;
    const size_t ordinary_blocks = partial == 0U ? full_blocks : full_blocks - 1U;

    if (ordinary_blocks != 0U) {
        if (batched != 0) {
            process_batched_blocks(
                &ctx->data_key, data_crypt, tweak, in, out, ordinary_blocks
            );
        } else {
            process_scalar_blocks(
                &ctx->data_key, data_crypt, tweak, in, out, ordinary_blocks
            );
        }
    }

    if (partial == 0U) {
        memset(tweak, 0, sizeof(tweak));
        return AES128_XTS_OK;
    }

    const size_t last_full_offset = ordinary_blocks * AES128_BLOCK_SIZE;
    const size_t partial_offset = full_blocks * AES128_BLOCK_SIZE;
    uint8_t last_full[AES128_BLOCK_SIZE];
    uint8_t tail[AES128_BLOCK_SIZE];
    uint8_t temporary[AES128_BLOCK_SIZE];
    uint8_t stolen[AES128_BLOCK_SIZE];
    uint8_t next_tweak[AES128_BLOCK_SIZE];

    memcpy(last_full, in + last_full_offset, AES128_BLOCK_SIZE);
    memset(tail, 0, sizeof(tail));
    memcpy(tail, in + partial_offset, partial);
    memcpy(next_tweak, tweak, sizeof(next_tweak));
    xts_mul_alpha(next_tweak);

    if (direction == XTS_ENCRYPT) {
        /* CC is the provisional ciphertext of the last complete block. */
        xex_one(&ctx->data_key, data_crypt, tweak, last_full, temporary);
        memcpy(stolen, tail, partial);
        memcpy(stolen + partial, temporary + partial, AES128_BLOCK_SIZE - partial);

        /* The partial ciphertext steals the first bytes of CC. */
        xex_one(
            &ctx->data_key, data_crypt, next_tweak, stolen,
            out + last_full_offset
        );
        memcpy(out + partial_offset, temporary, partial);
    } else {
        /* Recover PP with the next tweak, then reconstruct CC. */
        xex_one(&ctx->data_key, data_crypt, next_tweak, last_full, temporary);
        memcpy(stolen, tail, partial);
        memcpy(stolen + partial, temporary + partial, AES128_BLOCK_SIZE - partial);
        xex_one(
            &ctx->data_key, data_crypt, tweak, stolen,
            out + last_full_offset
        );
        memcpy(out + partial_offset, temporary, partial);
    }

    memset(tweak, 0, sizeof(tweak));
    memset(last_full, 0, sizeof(last_full));
    memset(tail, 0, sizeof(tail));
    memset(temporary, 0, sizeof(temporary));
    memset(stolen, 0, sizeof(stolen));
    memset(next_tweak, 0, sizeof(next_tweak));
    return AES128_XTS_OK;
}

int aes128_xts_init(
    aes128_xts_key_t *ctx,
    const uint8_t key[AES128_XTS_KEY_SIZE]
) {
    if (ctx == NULL || key == NULL) {
        return AES128_XTS_INVALID_ARGUMENT;
    }
    if (memcmp(key, key + AES128_KEY_SIZE, AES128_KEY_SIZE) == 0) {
        memset(ctx, 0, sizeof(*ctx));
        return AES128_XTS_WEAK_KEY;
    }
    if (aes128_init(&ctx->data_key, key) != 0 ||
        aes128_init(&ctx->tweak_key, key + AES128_KEY_SIZE) != 0) {
        aes128_xts_clear(ctx);
        return AES128_XTS_INVALID_ARGUMENT;
    }
    return AES128_XTS_OK;
}

void aes128_xts_clear(aes128_xts_key_t *ctx) {
    if (ctx != NULL) {
        aes128_clear(&ctx->data_key);
        aes128_clear(&ctx->tweak_key);
    }
}

int aes128_xts_aesni_supported(void) {
    return aes128_aesni_supported();
}

int aes128_xts_encrypt_ref(
    const aes128_xts_key_t *ctx,
    const uint8_t tweak[AES128_BLOCK_SIZE],
    const uint8_t *plaintext,
    uint8_t *ciphertext,
    size_t length
) {
    return xts_crypt(
        ctx, tweak, plaintext, ciphertext, length, XTS_ENCRYPT, 0, 0
    );
}

int aes128_xts_decrypt_ref(
    const aes128_xts_key_t *ctx,
    const uint8_t tweak[AES128_BLOCK_SIZE],
    const uint8_t *ciphertext,
    uint8_t *plaintext,
    size_t length
) {
    return xts_crypt(
        ctx, tweak, ciphertext, plaintext, length, XTS_DECRYPT, 0, 0
    );
}

int aes128_xts_encrypt_aesni_scalar(
    const aes128_xts_key_t *ctx,
    const uint8_t tweak[AES128_BLOCK_SIZE],
    const uint8_t *plaintext,
    uint8_t *ciphertext,
    size_t length
) {
    return xts_crypt(
        ctx, tweak, plaintext, ciphertext, length, XTS_ENCRYPT, 0,
        aes128_xts_aesni_supported()
    );
}

int aes128_xts_decrypt_aesni_scalar(
    const aes128_xts_key_t *ctx,
    const uint8_t tweak[AES128_BLOCK_SIZE],
    const uint8_t *ciphertext,
    uint8_t *plaintext,
    size_t length
) {
    return xts_crypt(
        ctx, tweak, ciphertext, plaintext, length, XTS_DECRYPT, 0,
        aes128_xts_aesni_supported()
    );
}

int aes128_xts_encrypt_aesni_batch(
    const aes128_xts_key_t *ctx,
    const uint8_t tweak[AES128_BLOCK_SIZE],
    const uint8_t *plaintext,
    uint8_t *ciphertext,
    size_t length
) {
    return xts_crypt(
        ctx, tweak, plaintext, ciphertext, length, XTS_ENCRYPT, 1,
        aes128_xts_aesni_supported()
    );
}

int aes128_xts_decrypt_aesni_batch(
    const aes128_xts_key_t *ctx,
    const uint8_t tweak[AES128_BLOCK_SIZE],
    const uint8_t *ciphertext,
    uint8_t *plaintext,
    size_t length
) {
    return xts_crypt(
        ctx, tweak, ciphertext, plaintext, length, XTS_DECRYPT, 1,
        aes128_xts_aesni_supported()
    );
}
