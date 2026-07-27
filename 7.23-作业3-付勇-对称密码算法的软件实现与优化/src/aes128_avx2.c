#include "aes128.h"
#include "aes128_tables.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
#include <immintrin.h>

static uint32_t load_be32(const uint8_t p[4]) {
    return ((uint32_t)p[0] << 24)
         | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)
         | (uint32_t)p[3];
}

static uint32_t round_key_word(const aes128_key_t *ctx, size_t word_index) {
    return load_be32(&ctx->round_keys[word_index * 4U]);
}

__attribute__((target("avx2")))
static __m256i byte_swap_words(__m256i value) {
    const __m256i mask = _mm256_setr_epi8(
         3,  2,  1,  0,  7,  6,  5,  4,
        11, 10,  9,  8, 15, 14, 13, 12,
         3,  2,  1,  0,  7,  6,  5,  4,
        11, 10,  9,  8, 15, 14, 13, 12
    );
    return _mm256_shuffle_epi8(value, mask);
}

__attribute__((target("avx2")))
static __m256i gather_table(const uint32_t table[256], __m256i indices) {
    return _mm256_i32gather_epi32((const int *)(const void *)table, indices, 4);
}

__attribute__((target("avx2")))
static __m256i table_round_word(
    __m256i a, __m256i b, __m256i c, __m256i d, uint32_t round_key
) {
    const __m256i mask_ff = _mm256_set1_epi32(0xff);
    const __m256i i0 = _mm256_srli_epi32(a, 24);
    const __m256i i1 = _mm256_and_si256(_mm256_srli_epi32(b, 16), mask_ff);
    const __m256i i2 = _mm256_and_si256(_mm256_srli_epi32(c, 8), mask_ff);
    const __m256i i3 = _mm256_and_si256(d, mask_ff);

    __m256i result = gather_table(aes128_te0, i0);
    result = _mm256_xor_si256(result, gather_table(aes128_te1, i1));
    result = _mm256_xor_si256(result, gather_table(aes128_te2, i2));
    result = _mm256_xor_si256(result, gather_table(aes128_te3, i3));
    return _mm256_xor_si256(result, _mm256_set1_epi32((int)round_key));
}

__attribute__((target("avx2")))
static __m256i final_round_word(
    __m256i a, __m256i b, __m256i c, __m256i d, uint32_t round_key
) {
    const __m256i mask_ff = _mm256_set1_epi32(0xff);
    const __m256i i0 = _mm256_srli_epi32(a, 24);
    const __m256i i1 = _mm256_and_si256(_mm256_srli_epi32(b, 16), mask_ff);
    const __m256i i2 = _mm256_and_si256(_mm256_srli_epi32(c, 8), mask_ff);
    const __m256i i3 = _mm256_and_si256(d, mask_ff);

    /* Each Te0 entry contains the S-box byte in bits 16..23 and 8..15. */
    __m256i x0 = _mm256_and_si256(_mm256_srli_epi32(gather_table(aes128_te0, i0), 16), mask_ff);
    __m256i x1 = _mm256_and_si256(_mm256_srli_epi32(gather_table(aes128_te0, i1), 16), mask_ff);
    __m256i x2 = _mm256_and_si256(_mm256_srli_epi32(gather_table(aes128_te0, i2), 16), mask_ff);
    __m256i x3 = _mm256_and_si256(_mm256_srli_epi32(gather_table(aes128_te0, i3), 16), mask_ff);

    x0 = _mm256_slli_epi32(x0, 24);
    x1 = _mm256_slli_epi32(x1, 16);
    x2 = _mm256_slli_epi32(x2, 8);

    __m256i result = _mm256_xor_si256(x0, x1);
    result = _mm256_xor_si256(result, x2);
    result = _mm256_xor_si256(result, x3);
    return _mm256_xor_si256(result, _mm256_set1_epi32((int)round_key));
}

__attribute__((target("avx2")))
static void store_scattered_words(uint8_t *out, size_t word_offset, __m256i words) {
    uint32_t lanes[8];
    words = byte_swap_words(words);
    _mm256_storeu_si256((__m256i *)(void *)lanes, words);
    for (size_t lane = 0; lane < 8; ++lane) {
        memcpy(out + lane * AES128_BLOCK_SIZE + word_offset, &lanes[lane], sizeof(lanes[lane]));
    }
}

__attribute__((target("avx2")))
static void encrypt_eight_blocks_avx2(
    const aes128_key_t *ctx, const uint8_t *in, uint8_t *out
) {
    const __m256i block_offsets = _mm256_setr_epi32(0, 16, 32, 48, 64, 80, 96, 112);

    __m256i s0 = _mm256_i32gather_epi32((const int *)(const void *)(in + 0), block_offsets, 1);
    __m256i s1 = _mm256_i32gather_epi32((const int *)(const void *)(in + 4), block_offsets, 1);
    __m256i s2 = _mm256_i32gather_epi32((const int *)(const void *)(in + 8), block_offsets, 1);
    __m256i s3 = _mm256_i32gather_epi32((const int *)(const void *)(in + 12), block_offsets, 1);

    s0 = _mm256_xor_si256(byte_swap_words(s0), _mm256_set1_epi32((int)round_key_word(ctx, 0)));
    s1 = _mm256_xor_si256(byte_swap_words(s1), _mm256_set1_epi32((int)round_key_word(ctx, 1)));
    s2 = _mm256_xor_si256(byte_swap_words(s2), _mm256_set1_epi32((int)round_key_word(ctx, 2)));
    s3 = _mm256_xor_si256(byte_swap_words(s3), _mm256_set1_epi32((int)round_key_word(ctx, 3)));

    for (size_t round = 1; round < AES128_ROUNDS; ++round) {
        const size_t k = round * 4U;
        const __m256i t0 = table_round_word(s0, s1, s2, s3, round_key_word(ctx, k + 0U));
        const __m256i t1 = table_round_word(s1, s2, s3, s0, round_key_word(ctx, k + 1U));
        const __m256i t2 = table_round_word(s2, s3, s0, s1, round_key_word(ctx, k + 2U));
        const __m256i t3 = table_round_word(s3, s0, s1, s2, round_key_word(ctx, k + 3U));
        s0 = t0;
        s1 = t1;
        s2 = t2;
        s3 = t3;
    }

    const __m256i t0 = final_round_word(s0, s1, s2, s3, round_key_word(ctx, 40));
    const __m256i t1 = final_round_word(s1, s2, s3, s0, round_key_word(ctx, 41));
    const __m256i t2 = final_round_word(s2, s3, s0, s1, round_key_word(ctx, 42));
    const __m256i t3 = final_round_word(s3, s0, s1, s2, round_key_word(ctx, 43));

    store_scattered_words(out, 0, t0);
    store_scattered_words(out, 4, t1);
    store_scattered_words(out, 8, t2);
    store_scattered_words(out, 12, t3);
    _mm256_zeroupper();
}
#endif

int aes128_avx2_supported(void) {
#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
    __builtin_cpu_init();
    return __builtin_cpu_supports("avx2") != 0;
#else
    return 0;
#endif
}

void aes128_encrypt_blocks_avx2(
    const aes128_key_t *ctx,
    const uint8_t *in,
    uint8_t *out,
    size_t blocks
) {
#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
    if (aes128_avx2_supported()) {
        while (blocks >= 8U) {
            encrypt_eight_blocks_avx2(ctx, in, out);
            in += 8U * AES128_BLOCK_SIZE;
            out += 8U * AES128_BLOCK_SIZE;
            blocks -= 8U;
        }
    }
#endif
    if (blocks != 0U) {
        aes128_encrypt_blocks_ttable(ctx, in, out, blocks);
    }
}
