#include "aes128.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
#include <immintrin.h>
#endif

typedef void (*encrypt_blocks_fn)(
    const aes128_key_t *, const uint8_t *, uint8_t *, size_t
);

static int ctr_validate(
    const aes128_key_t *ctx,
    const uint8_t counter[AES128_BLOCK_SIZE],
    const uint8_t *in,
    uint8_t *out,
    size_t length
) {
    if (ctx == NULL || counter == NULL) {
        return AES128_CTR_INVALID_ARGUMENT;
    }
    if (length != 0U && (in == NULL || out == NULL)) {
        return AES128_CTR_INVALID_ARGUMENT;
    }
    return AES128_CTR_OK;
}

/* Add a non-negative block count to a big-endian 128-bit counter.
 * Returns 1 on success and 0 if the addition would wrap modulo 2^128. */
static int counter_add_be128(uint8_t counter[AES128_BLOCK_SIZE], size_t blocks) {
    size_t carry = blocks;

    for (size_t offset = 0; offset < AES128_BLOCK_SIZE; ++offset) {
        const size_t index = AES128_BLOCK_SIZE - 1U - offset;
        const size_t sum = (size_t)counter[index] + (carry & (size_t)UINT8_MAX);
        counter[index] = (uint8_t)(sum & (size_t)UINT8_MAX);
        carry = (carry >> 8U) + (sum >> 8U);
    }
    return carry == 0U;
}

static size_t blocks_for_length(size_t length) {
    return length / AES128_BLOCK_SIZE + (length % AES128_BLOCK_SIZE != 0U ? 1U : 0U);
}

static int ctr_preflight(
    const aes128_key_t *ctx,
    const uint8_t counter[AES128_BLOCK_SIZE],
    const uint8_t *in,
    uint8_t *out,
    size_t length
) {
    const int valid = ctr_validate(ctx, counter, in, out, length);
    if (valid != AES128_CTR_OK) {
        return valid;
    }

    uint8_t final_counter[AES128_BLOCK_SIZE];
    memcpy(final_counter, counter, sizeof(final_counter));
    if (!counter_add_be128(final_counter, blocks_for_length(length))) {
        return AES128_CTR_COUNTER_EXHAUSTED;
    }
    return AES128_CTR_OK;
}

static void xor_bytes(
    const uint8_t *in, const uint8_t *keystream, uint8_t *out, size_t length
) {
    for (size_t i = 0; i < length; ++i) {
        out[i] = (uint8_t)(in[i] ^ keystream[i]);
    }
}

static int ctr_crypt_scalar(
    const aes128_key_t *ctx,
    uint8_t counter[AES128_BLOCK_SIZE],
    const uint8_t *in,
    uint8_t *out,
    size_t length,
    encrypt_blocks_fn encrypt
) {
    const int status = ctr_preflight(ctx, counter, in, out, length);
    if (status != AES128_CTR_OK || length == 0U) {
        return status;
    }

    uint8_t keystream[AES128_BLOCK_SIZE];
    while (length != 0U) {
        const size_t chunk = length < AES128_BLOCK_SIZE ? length : AES128_BLOCK_SIZE;
        encrypt(ctx, counter, keystream, 1U);
        xor_bytes(in, keystream, out, chunk);
        (void)counter_add_be128(counter, 1U);
        in += chunk;
        out += chunk;
        length -= chunk;
    }
    memset(keystream, 0, sizeof(keystream));
    return AES128_CTR_OK;
}

static int ctr_crypt_batched(
    const aes128_key_t *ctx,
    uint8_t counter[AES128_BLOCK_SIZE],
    const uint8_t *in,
    uint8_t *out,
    size_t length,
    encrypt_blocks_fn encrypt
) {
    const int status = ctr_preflight(ctx, counter, in, out, length);
    if (status != AES128_CTR_OK || length == 0U) {
        return status;
    }

    uint8_t counters[8U * AES128_BLOCK_SIZE];
    uint8_t keystream[8U * AES128_BLOCK_SIZE];

    while (length >= 8U * AES128_BLOCK_SIZE) {
        uint8_t next[AES128_BLOCK_SIZE];
        memcpy(next, counter, sizeof(next));
        for (size_t lane = 0; lane < 8U; ++lane) {
            memcpy(counters + lane * AES128_BLOCK_SIZE, next, AES128_BLOCK_SIZE);
            (void)counter_add_be128(next, 1U);
        }
        encrypt(ctx, counters, keystream, 8U);
        xor_bytes(in, keystream, out, 8U * AES128_BLOCK_SIZE);
        memcpy(counter, next, AES128_BLOCK_SIZE);
        in += 8U * AES128_BLOCK_SIZE;
        out += 8U * AES128_BLOCK_SIZE;
        length -= 8U * AES128_BLOCK_SIZE;
    }

    while (length != 0U) {
        const size_t chunk = length < AES128_BLOCK_SIZE ? length : AES128_BLOCK_SIZE;
        encrypt(ctx, counter, keystream, 1U);
        xor_bytes(in, keystream, out, chunk);
        (void)counter_add_be128(counter, 1U);
        in += chunk;
        out += chunk;
        length -= chunk;
    }

    memset(counters, 0, sizeof(counters));
    memset(keystream, 0, sizeof(keystream));
    return AES128_CTR_OK;
}

#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
static uint32_t load_be32(const uint8_t src[4]) {
    return ((uint32_t)src[0] << 24U) |
           ((uint32_t)src[1] << 16U) |
           ((uint32_t)src[2] << 8U) |
           (uint32_t)src[3];
}

__attribute__((target("aes,ssse3,sse4.1,sse2")))
static void make_counter_batch_x86(
    const uint8_t counter[AES128_BLOCK_SIZE],
    uint8_t *counter_blocks,
    size_t count
) {
    const __m128i byte_reverse_each_word = _mm_setr_epi8(
         3, 2, 1, 0,  7, 6, 5, 4,
        11,10, 9, 8, 15,14,13,12
    );
    const __m128i input = _mm_loadu_si128((const __m128i *)(const void *)counter);
    const __m128i host_words = _mm_shuffle_epi8(input, byte_reverse_each_word);
    const uint32_t low = (uint32_t)_mm_extract_epi32(host_words, 3);

    for (size_t lane = 0; lane < count; ++lane) {
        const uint32_t value = low + (uint32_t)lane;
        __m128i block = _mm_insert_epi32(host_words, (int)value, 3);
        block = _mm_shuffle_epi8(block, byte_reverse_each_word);
        _mm_storeu_si128(
            (__m128i *)(void *)(counter_blocks + lane * AES128_BLOCK_SIZE), block
        );
    }
}

__attribute__((target("aes,ssse3,sse4.1,sse2")))
static void xor_full_blocks_x86(
    const uint8_t *in, const uint8_t *keystream, uint8_t *out, size_t blocks
) {
    for (size_t lane = 0; lane < blocks; ++lane) {
        const size_t offset = lane * AES128_BLOCK_SIZE;
        const __m128i plaintext = _mm_loadu_si128(
            (const __m128i *)(const void *)(in + offset)
        );
        const __m128i stream = _mm_loadu_si128(
            (const __m128i *)(const void *)(keystream + offset)
        );
        _mm_storeu_si128(
            (__m128i *)(void *)(out + offset), _mm_xor_si128(plaintext, stream)
        );
    }
}

__attribute__((target("aes,ssse3,sse4.1,sse2")))
static int ctr_crypt_aesni_x86(
    const aes128_key_t *ctx,
    uint8_t counter[AES128_BLOCK_SIZE],
    const uint8_t *in,
    uint8_t *out,
    size_t length
) {
    uint8_t counter_blocks[8U * AES128_BLOCK_SIZE];
    uint8_t keystream[8U * AES128_BLOCK_SIZE];

    while (length >= 8U * AES128_BLOCK_SIZE) {
        const uint32_t low = load_be32(counter + 12U);
        if (low <= UINT32_MAX - 7U) {
            make_counter_batch_x86(counter, counter_blocks, 8U);
            aes128_encrypt_blocks_aesni(ctx, counter_blocks, keystream, 8U);
            xor_full_blocks_x86(in, keystream, out, 8U);
            (void)counter_add_be128(counter, 8U);
            in += 8U * AES128_BLOCK_SIZE;
            out += 8U * AES128_BLOCK_SIZE;
            length -= 8U * AES128_BLOCK_SIZE;
        } else {
            aes128_encrypt_blocks_aesni(ctx, counter, keystream, 1U);
            xor_full_blocks_x86(in, keystream, out, 1U);
            (void)counter_add_be128(counter, 1U);
            in += AES128_BLOCK_SIZE;
            out += AES128_BLOCK_SIZE;
            length -= AES128_BLOCK_SIZE;
        }
    }

    if (length >= 4U * AES128_BLOCK_SIZE) {
        const uint32_t low = load_be32(counter + 12U);
        if (low <= UINT32_MAX - 3U) {
            make_counter_batch_x86(counter, counter_blocks, 4U);
            aes128_encrypt_blocks_aesni(ctx, counter_blocks, keystream, 4U);
            xor_full_blocks_x86(in, keystream, out, 4U);
            (void)counter_add_be128(counter, 4U);
            in += 4U * AES128_BLOCK_SIZE;
            out += 4U * AES128_BLOCK_SIZE;
            length -= 4U * AES128_BLOCK_SIZE;
        }
    }

    while (length != 0U) {
        const size_t chunk = length < AES128_BLOCK_SIZE ? length : AES128_BLOCK_SIZE;
        aes128_encrypt_blocks_aesni(ctx, counter, keystream, 1U);
        if (chunk == AES128_BLOCK_SIZE) {
            xor_full_blocks_x86(in, keystream, out, 1U);
        } else {
            xor_bytes(in, keystream, out, chunk);
        }
        (void)counter_add_be128(counter, 1U);
        in += chunk;
        out += chunk;
        length -= chunk;
    }

    memset(counter_blocks, 0, sizeof(counter_blocks));
    memset(keystream, 0, sizeof(keystream));
    return AES128_CTR_OK;
}
#endif

int aes128_ctr_aesni_supported(void) {
#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
    __builtin_cpu_init();
    return aes128_aesni_supported() &&
           __builtin_cpu_supports("ssse3") != 0 &&
           __builtin_cpu_supports("sse4.1") != 0;
#else
    return 0;
#endif
}

int aes128_ctr_crypt_ref(
    const aes128_key_t *ctx,
    uint8_t counter[AES128_BLOCK_SIZE],
    const uint8_t *in,
    uint8_t *out,
    size_t length
) {
    return ctr_crypt_scalar(
        ctx, counter, in, out, length, aes128_encrypt_blocks_ref
    );
}

int aes128_ctr_crypt_ttable(
    const aes128_key_t *ctx,
    uint8_t counter[AES128_BLOCK_SIZE],
    const uint8_t *in,
    uint8_t *out,
    size_t length
) {
    return ctr_crypt_scalar(
        ctx, counter, in, out, length, aes128_encrypt_blocks_ttable
    );
}

int aes128_ctr_crypt_avx2(
    const aes128_key_t *ctx,
    uint8_t counter[AES128_BLOCK_SIZE],
    const uint8_t *in,
    uint8_t *out,
    size_t length
) {
    return ctr_crypt_batched(
        ctx, counter, in, out, length, aes128_encrypt_blocks_avx2
    );
}

int aes128_ctr_crypt_aesni(
    const aes128_key_t *ctx,
    uint8_t counter[AES128_BLOCK_SIZE],
    const uint8_t *in,
    uint8_t *out,
    size_t length
) {
    const int status = ctr_preflight(ctx, counter, in, out, length);
    if (status != AES128_CTR_OK || length == 0U) {
        return status;
    }

#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
    if (aes128_ctr_aesni_supported()) {
        return ctr_crypt_aesni_x86(ctx, counter, in, out, length);
    }
#endif
    return ctr_crypt_batched(
        ctx, counter, in, out, length, aes128_encrypt_blocks_ttable
    );
}
