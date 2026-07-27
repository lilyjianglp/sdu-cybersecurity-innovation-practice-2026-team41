#include "aes128.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
#include <immintrin.h>
#endif

typedef void (*encrypt_block_fn)(
    const aes128_key_t *, const uint8_t[AES128_BLOCK_SIZE],
    uint8_t[AES128_BLOCK_SIZE]
);

typedef void (*encrypt_blocks_fn)(
    const aes128_key_t *, const uint8_t *, uint8_t *, size_t
);

typedef void (*ghash_multiply_fn)(
    const uint8_t[AES128_BLOCK_SIZE], const uint8_t[AES128_BLOCK_SIZE],
    uint8_t[AES128_BLOCK_SIZE]
);

typedef struct {
    encrypt_block_fn encrypt_block;
    encrypt_blocks_fn encrypt_blocks;
    ghash_multiply_fn multiply;
} gcm_backend_t;

static void clear_bytes(void *buffer, size_t length) {
    volatile uint8_t *p = (volatile uint8_t *)buffer;
    while (length != 0U) {
        *p++ = 0;
        --length;
    }
}

static void xor_block(uint8_t dst[16], const uint8_t src[16]) {
    for (size_t i = 0; i < 16U; ++i) {
        dst[i] ^= src[i];
    }
}

static uint64_t load_be64(const uint8_t input[8]) {
    uint64_t value = 0;
    for (size_t i = 0; i < 8U; ++i) {
        value = (value << 8U) | (uint64_t)input[i];
    }
    return value;
}

static void store_be64_word(uint8_t output[8], uint64_t value) {
    for (size_t i = 0; i < 8U; ++i) {
        output[7U - i] = (uint8_t)(value >> (i * 8U));
    }
}

/* Portable SP 800-38D multiplication. Inputs and output use the external
 * big-endian GHASH bit ordering. Two 64-bit words keep the implementation
 * readable while avoiding byte-array shifts inside every bit iteration. */
static void ghash_multiply_ref(
    const uint8_t x[16], const uint8_t y[16], uint8_t out[16]
) {
    uint64_t z_hi = 0;
    uint64_t z_lo = 0;
    uint64_t v_hi = load_be64(y);
    uint64_t v_lo = load_be64(y + 8U);

    for (size_t bit = 0; bit < 128U; ++bit) {
        const uint64_t selected = UINT64_C(0) -
            (uint64_t)(((uint32_t)x[bit >> 3U] >> (7U - (bit & 7U))) & UINT32_C(1));
        z_hi ^= v_hi & selected;
        z_lo ^= v_lo & selected;

        const uint64_t lsb = v_lo & UINT64_C(1);
        v_lo = (v_lo >> 1U) | (v_hi << 63U);
        v_hi = (v_hi >> 1U) ^
            (UINT64_C(0xe100000000000000) & (UINT64_C(0) - lsb));
    }

    store_be64_word(out, z_hi);
    store_be64_word(out + 8U, z_lo);
}

#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
__attribute__((target("pclmul,ssse3,sse2")))
static __m128i reverse_bits_in_bytes(__m128i value) {
    const __m128i nibble_mask = _mm_set1_epi8(0x0f);
    const __m128i reverse_nibbles = _mm_setr_epi8(
        0x0,0x8,0x4,0xc,0x2,0xa,0x6,0xe,
        0x1,0x9,0x5,0xd,0x3,0xb,0x7,0xf
    );
    const __m128i low = _mm_and_si128(value, nibble_mask);
    const __m128i high = _mm_and_si128(_mm_srli_epi16(value, 4), nibble_mask);
    const __m128i reversed_low = _mm_shuffle_epi8(reverse_nibbles, low);
    const __m128i reversed_high = _mm_shuffle_epi8(reverse_nibbles, high);
    return _mm_or_si128(_mm_slli_epi16(reversed_low, 4), reversed_high);
}

/* Reduce a 256-bit little-endian polynomial modulo
 * x^128 + x^7 + x^2 + x + 1. */
static void reduce_product_le(
    const uint64_t low[2], const uint64_t high[2], uint64_t reduced[2]
) {
    const uint64_t h0 = high[0];
    const uint64_t h1 = high[1];

    uint64_t t0 = h0 ^ (h0 << 1U) ^ (h0 << 2U) ^ (h0 << 7U);
    uint64_t t1 = h1;
    t1 ^= (h1 << 1U) | (h0 >> 63U);
    t1 ^= (h1 << 2U) | (h0 >> 62U);
    t1 ^= (h1 << 7U) | (h0 >> 57U);

    const uint64_t overflow = (h1 >> 63U) ^ (h1 >> 62U) ^ (h1 >> 57U);
    t0 ^= overflow ^ (overflow << 1U) ^ (overflow << 2U) ^ (overflow << 7U);

    reduced[0] = low[0] ^ t0;
    reduced[1] = low[1] ^ t1;
}

__attribute__((target("pclmul,ssse3,sse2")))
static void ghash_multiply_pclmul_impl(
    const uint8_t x[16], const uint8_t y[16], uint8_t out[16]
) {
    __m128i a = _mm_loadu_si128((const __m128i *)(const void *)x);
    __m128i b = _mm_loadu_si128((const __m128i *)(const void *)y);
    a = reverse_bits_in_bytes(a);
    b = reverse_bits_in_bytes(b);

    const __m128i p00 = _mm_clmulepi64_si128(a, b, 0x00);
    const __m128i p01 = _mm_clmulepi64_si128(a, b, 0x01);
    const __m128i p10 = _mm_clmulepi64_si128(a, b, 0x10);
    const __m128i p11 = _mm_clmulepi64_si128(a, b, 0x11);
    const __m128i cross = _mm_xor_si128(p01, p10);
    const __m128i product_low = _mm_xor_si128(p00, _mm_slli_si128(cross, 8));
    const __m128i product_high = _mm_xor_si128(p11, _mm_srli_si128(cross, 8));

    uint64_t low[2];
    uint64_t high[2];
    uint64_t reduced[2];
    _mm_storeu_si128((__m128i *)(void *)low, product_low);
    _mm_storeu_si128((__m128i *)(void *)high, product_high);
    reduce_product_le(low, high, reduced);

    __m128i result = _mm_loadu_si128((const __m128i *)(const void *)reduced);
    result = reverse_bits_in_bytes(result);
    _mm_storeu_si128((__m128i *)(void *)out, result);

    clear_bytes(low, sizeof(low));
    clear_bytes(high, sizeof(high));
    clear_bytes(reduced, sizeof(reduced));
}
#endif

int aes128_gcm_pclmul_supported(void) {
#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
    __builtin_cpu_init();
    return __builtin_cpu_supports("pclmul") != 0 &&
           __builtin_cpu_supports("ssse3") != 0 &&
           aes128_aesni_supported();
#else
    return 0;
#endif
}

static void ghash_multiply_pclmul_dispatch(
    const uint8_t x[16], const uint8_t y[16], uint8_t out[16]
) {
#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
    if (aes128_gcm_pclmul_supported()) {
        ghash_multiply_pclmul_impl(x, y, out);
        return;
    }
#endif
    ghash_multiply_ref(x, y, out);
}

static void store_be64(uint8_t out[8], uint64_t value) {
    for (size_t i = 0; i < 8U; ++i) {
        out[7U - i] = (uint8_t)(value >> (i * 8U));
    }
}

static int length_to_bits(size_t bytes, uint64_t *bits) {
#if SIZE_MAX > UINT64_MAX
    if (bytes > (size_t)(UINT64_MAX / 8U)) {
        return 0;
    }
#endif
    if ((uint64_t)bytes > UINT64_MAX / UINT64_C(8)) {
        return 0;
    }
    *bits = (uint64_t)bytes * UINT64_C(8);
    return 1;
}

static void ghash_update(
    uint8_t y[16], const uint8_t h[16], const uint8_t *data, size_t length,
    ghash_multiply_fn multiply
) {
    while (length >= 16U) {
        xor_block(y, data);
        multiply(y, h, y);
        data += 16U;
        length -= 16U;
    }
    if (length != 0U) {
        uint8_t last[16] = {0};
        memcpy(last, data, length);
        xor_block(y, last);
        multiply(y, h, y);
        clear_bytes(last, sizeof(last));
    }
}

static void ghash_all(
    const uint8_t h[16],
    const uint8_t *aad, size_t aad_length,
    const uint8_t *ciphertext, size_t ciphertext_length,
    ghash_multiply_fn multiply,
    uint8_t out[16]
) {
    uint64_t aad_bits = 0;
    uint64_t ciphertext_bits = 0;
    uint8_t lengths[16];
    memset(out, 0, 16U);

    (void)length_to_bits(aad_length, &aad_bits);
    (void)length_to_bits(ciphertext_length, &ciphertext_bits);
    ghash_update(out, h, aad, aad_length, multiply);
    ghash_update(out, h, ciphertext, ciphertext_length, multiply);
    store_be64(lengths, aad_bits);
    store_be64(lengths + 8U, ciphertext_bits);
    xor_block(out, lengths);
    multiply(out, h, out);
    clear_bytes(lengths, sizeof(lengths));
}

static int derive_j0(
    const uint8_t h[16], const uint8_t *iv, size_t iv_length,
    ghash_multiply_fn multiply, uint8_t j0[16]
) {
    if (iv_length == 12U) {
        memcpy(j0, iv, 12U);
        j0[12] = 0;
        j0[13] = 0;
        j0[14] = 0;
        j0[15] = 1;
        return AES128_GCM_OK;
    }

    uint64_t iv_bits = 0;
    if (!length_to_bits(iv_length, &iv_bits)) {
        return AES128_GCM_LENGTH_LIMIT;
    }

    uint8_t lengths[16] = {0};
    memset(j0, 0, 16U);
    ghash_update(j0, h, iv, iv_length, multiply);
    store_be64(lengths + 8U, iv_bits);
    xor_block(j0, lengths);
    multiply(j0, h, j0);
    clear_bytes(lengths, sizeof(lengths));
    return AES128_GCM_OK;
}

static void increment32(uint8_t counter[16]) {
    uint32_t value = ((uint32_t)counter[12] << 24U) |
                     ((uint32_t)counter[13] << 16U) |
                     ((uint32_t)counter[14] << 8U) |
                     (uint32_t)counter[15];
    value += UINT32_C(1);
    counter[12] = (uint8_t)(value >> 24U);
    counter[13] = (uint8_t)(value >> 16U);
    counter[14] = (uint8_t)(value >> 8U);
    counter[15] = (uint8_t)value;
}

static int gctr(
    const aes128_key_t *ctx, const uint8_t j0[16],
    const uint8_t *input, uint8_t *output, size_t length,
    encrypt_blocks_fn encrypt_blocks
) {
    const size_t blocks = length / 16U + (length % 16U != 0U ? 1U : 0U);
    if (blocks > (size_t)UINT32_MAX - 1U) {
        return AES128_GCM_LENGTH_LIMIT;
    }
    if (length == 0U) {
        return AES128_GCM_OK;
    }

    uint8_t counter[16];
    uint8_t counters[8U * 16U];
    uint8_t stream[8U * 16U];
    memcpy(counter, j0, sizeof(counter));

    size_t remaining = length;
    while (remaining >= 8U * 16U) {
        for (size_t i = 0; i < 8U; ++i) {
            increment32(counter);
            memcpy(counters + i * 16U, counter, 16U);
        }
        encrypt_blocks(ctx, counters, stream, 8U);
        for (size_t i = 0; i < 8U * 16U; ++i) {
            output[i] = (uint8_t)(input[i] ^ stream[i]);
        }
        input += 8U * 16U;
        output += 8U * 16U;
        remaining -= 8U * 16U;
    }

    if (remaining != 0U) {
        const size_t full_blocks = remaining / 16U;
        const size_t tail = remaining % 16U;
        const size_t count = full_blocks + (tail != 0U ? 1U : 0U);
        for (size_t i = 0; i < count; ++i) {
            increment32(counter);
            memcpy(counters + i * 16U, counter, 16U);
        }
        encrypt_blocks(ctx, counters, stream, count);
        for (size_t i = 0; i < remaining; ++i) {
            output[i] = (uint8_t)(input[i] ^ stream[i]);
        }
    }

    clear_bytes(counter, sizeof(counter));
    clear_bytes(counters, sizeof(counters));
    clear_bytes(stream, sizeof(stream));
    return AES128_GCM_OK;
}

static int constant_time_equal(const uint8_t *a, const uint8_t *b, size_t length) {
    uint8_t diff = 0;
    for (size_t i = 0; i < length; ++i) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

static int valid_tag_length(size_t tag_length) {
    return tag_length == 4U || tag_length == 8U ||
           (tag_length >= 12U && tag_length <= 16U);
}

static int validate_common(
    const aes128_key_t *ctx,
    const uint8_t *iv, size_t iv_length,
    const uint8_t *aad, size_t aad_length,
    const uint8_t *input, uint8_t *output, size_t length,
    const uint8_t *tag, size_t tag_length
) {
    if (ctx == NULL || iv == NULL || iv_length == 0U || tag == NULL ||
        !valid_tag_length(tag_length)) {
        return AES128_GCM_INVALID_ARGUMENT;
    }
    if (aad_length != 0U && aad == NULL) {
        return AES128_GCM_INVALID_ARGUMENT;
    }
    if (length != 0U && (input == NULL || output == NULL)) {
        return AES128_GCM_INVALID_ARGUMENT;
    }

    uint64_t ignored = 0;
    if (!length_to_bits(iv_length, &ignored) ||
        !length_to_bits(aad_length, &ignored) ||
        !length_to_bits(length, &ignored)) {
        return AES128_GCM_LENGTH_LIMIT;
    }
    const size_t blocks = length / 16U + (length % 16U != 0U ? 1U : 0U);
    if (blocks > (size_t)UINT32_MAX - 1U) {
        return AES128_GCM_LENGTH_LIMIT;
    }
    return AES128_GCM_OK;
}

static int gcm_encrypt_generic(
    const gcm_backend_t *backend,
    const aes128_key_t *ctx,
    const uint8_t *iv, size_t iv_length,
    const uint8_t *aad, size_t aad_length,
    const uint8_t *plaintext, uint8_t *ciphertext, size_t length,
    uint8_t *tag, size_t tag_length
) {
    const int valid = validate_common(
        ctx, iv, iv_length, aad, aad_length,
        plaintext, ciphertext, length, tag, tag_length
    );
    if (valid != AES128_GCM_OK) {
        return valid;
    }

    uint8_t zero[16] = {0};
    uint8_t h[16];
    uint8_t j0[16];
    uint8_t s[16];
    uint8_t encrypted_j0[16];
    backend->encrypt_block(ctx, zero, h);

    int status = derive_j0(h, iv, iv_length, backend->multiply, j0);
    if (status == AES128_GCM_OK) {
        status = gctr(ctx, j0, plaintext, ciphertext, length, backend->encrypt_blocks);
    }
    if (status == AES128_GCM_OK) {
        ghash_all(h, aad, aad_length, ciphertext, length, backend->multiply, s);
        backend->encrypt_block(ctx, j0, encrypted_j0);
        for (size_t i = 0; i < tag_length; ++i) {
            tag[i] = (uint8_t)(encrypted_j0[i] ^ s[i]);
        }
    }

    clear_bytes(h, sizeof(h));
    clear_bytes(j0, sizeof(j0));
    clear_bytes(s, sizeof(s));
    clear_bytes(encrypted_j0, sizeof(encrypted_j0));
    return status;
}

static int gcm_decrypt_generic(
    const gcm_backend_t *backend,
    const aes128_key_t *ctx,
    const uint8_t *iv, size_t iv_length,
    const uint8_t *aad, size_t aad_length,
    const uint8_t *ciphertext, uint8_t *plaintext, size_t length,
    const uint8_t *tag, size_t tag_length
) {
    const int valid = validate_common(
        ctx, iv, iv_length, aad, aad_length,
        ciphertext, plaintext, length, tag, tag_length
    );
    if (valid != AES128_GCM_OK) {
        return valid;
    }

    uint8_t zero[16] = {0};
    uint8_t h[16];
    uint8_t j0[16];
    uint8_t s[16];
    uint8_t encrypted_j0[16];
    uint8_t expected_tag[16];
    backend->encrypt_block(ctx, zero, h);

    int status = derive_j0(h, iv, iv_length, backend->multiply, j0);
    if (status == AES128_GCM_OK) {
        ghash_all(h, aad, aad_length, ciphertext, length, backend->multiply, s);
        backend->encrypt_block(ctx, j0, encrypted_j0);
        for (size_t i = 0; i < tag_length; ++i) {
            expected_tag[i] = (uint8_t)(encrypted_j0[i] ^ s[i]);
        }
        if (!constant_time_equal(expected_tag, tag, tag_length)) {
            status = AES128_GCM_TAG_MISMATCH;
        }
    }
    if (status == AES128_GCM_OK) {
        status = gctr(ctx, j0, ciphertext, plaintext, length, backend->encrypt_blocks);
    }

    clear_bytes(h, sizeof(h));
    clear_bytes(j0, sizeof(j0));
    clear_bytes(s, sizeof(s));
    clear_bytes(encrypted_j0, sizeof(encrypted_j0));
    clear_bytes(expected_tag, sizeof(expected_tag));
    return status;
}

static const gcm_backend_t GCM_REFERENCE = {
    aes128_encrypt_block_ref,
    aes128_encrypt_blocks_ref,
    ghash_multiply_ref
};

static const gcm_backend_t GCM_AESNI = {
    aes128_encrypt_block_aesni,
    aes128_encrypt_blocks_aesni,
    ghash_multiply_ref
};

static const gcm_backend_t GCM_PCLMUL = {
    aes128_encrypt_block_aesni,
    aes128_encrypt_blocks_aesni,
    ghash_multiply_pclmul_dispatch
};

#define DEFINE_GCM_WRAPPERS(name, backend) \
int aes128_gcm_encrypt_##name( \
    const aes128_key_t *ctx, const uint8_t *iv, size_t iv_length, \
    const uint8_t *aad, size_t aad_length, \
    const uint8_t *plaintext, uint8_t *ciphertext, size_t length, \
    uint8_t *tag, size_t tag_length \
) { \
    return gcm_encrypt_generic(&(backend), ctx, iv, iv_length, aad, aad_length, \
                               plaintext, ciphertext, length, tag, tag_length); \
} \
int aes128_gcm_decrypt_##name( \
    const aes128_key_t *ctx, const uint8_t *iv, size_t iv_length, \
    const uint8_t *aad, size_t aad_length, \
    const uint8_t *ciphertext, uint8_t *plaintext, size_t length, \
    const uint8_t *tag, size_t tag_length \
) { \
    return gcm_decrypt_generic(&(backend), ctx, iv, iv_length, aad, aad_length, \
                               ciphertext, plaintext, length, tag, tag_length); \
}

DEFINE_GCM_WRAPPERS(ref, GCM_REFERENCE)
DEFINE_GCM_WRAPPERS(aesni, GCM_AESNI)
DEFINE_GCM_WRAPPERS(pclmul, GCM_PCLMUL)
