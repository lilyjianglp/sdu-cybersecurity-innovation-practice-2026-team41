#include "aes128.h"

#include <stddef.h>
#include <stdint.h>

#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
#include <wmmintrin.h>

__attribute__((target("aes,sse2")))
static __m128i load_round_key(const aes128_key_t *ctx, size_t round) {
    return _mm_loadu_si128((const __m128i *)(const void *)&ctx->round_keys[round * AES128_BLOCK_SIZE]);
}

__attribute__((target("aes,sse2")))
static __m128i encrypt_state(__m128i state, const aes128_key_t *ctx) {
    state = _mm_xor_si128(state, load_round_key(ctx, 0));
    for (size_t round = 1; round < AES128_ROUNDS; ++round) {
        state = _mm_aesenc_si128(state, load_round_key(ctx, round));
    }
    return _mm_aesenclast_si128(state, load_round_key(ctx, AES128_ROUNDS));
}

__attribute__((target("aes,sse2")))
static __m128i decrypt_state(__m128i state, const aes128_key_t *ctx) {
    state = _mm_xor_si128(state, load_round_key(ctx, AES128_ROUNDS));
    for (size_t round = AES128_ROUNDS - 1U; round > 0U; --round) {
        const __m128i inverse_key = _mm_aesimc_si128(load_round_key(ctx, round));
        state = _mm_aesdec_si128(state, inverse_key);
    }
    return _mm_aesdeclast_si128(state, load_round_key(ctx, 0));
}

__attribute__((target("aes,sse2")))
static void encrypt_one_block_aesni(
    const aes128_key_t *ctx, const uint8_t *in, uint8_t *out
) {
    __m128i state = _mm_loadu_si128((const __m128i *)(const void *)in);
    state = encrypt_state(state, ctx);
    _mm_storeu_si128((__m128i *)(void *)out, state);
}

__attribute__((target("aes,sse2")))
static void decrypt_one_block_aesni(
    const aes128_key_t *ctx, const uint8_t *in, uint8_t *out
) {
    __m128i state = _mm_loadu_si128((const __m128i *)(const void *)in);
    state = decrypt_state(state, ctx);
    _mm_storeu_si128((__m128i *)(void *)out, state);
}

__attribute__((target("aes,sse2")))
static void encrypt_four_blocks_aesni(
    const aes128_key_t *ctx, const uint8_t *in, uint8_t *out
) {
    __m128i s0 = _mm_loadu_si128((const __m128i *)(const void *)(in + 0U * AES128_BLOCK_SIZE));
    __m128i s1 = _mm_loadu_si128((const __m128i *)(const void *)(in + 1U * AES128_BLOCK_SIZE));
    __m128i s2 = _mm_loadu_si128((const __m128i *)(const void *)(in + 2U * AES128_BLOCK_SIZE));
    __m128i s3 = _mm_loadu_si128((const __m128i *)(const void *)(in + 3U * AES128_BLOCK_SIZE));

    __m128i rk = load_round_key(ctx, 0);
    s0 = _mm_xor_si128(s0, rk);
    s1 = _mm_xor_si128(s1, rk);
    s2 = _mm_xor_si128(s2, rk);
    s3 = _mm_xor_si128(s3, rk);

    for (size_t round = 1; round < AES128_ROUNDS; ++round) {
        rk = load_round_key(ctx, round);
        s0 = _mm_aesenc_si128(s0, rk);
        s1 = _mm_aesenc_si128(s1, rk);
        s2 = _mm_aesenc_si128(s2, rk);
        s3 = _mm_aesenc_si128(s3, rk);
    }

    rk = load_round_key(ctx, AES128_ROUNDS);
    s0 = _mm_aesenclast_si128(s0, rk);
    s1 = _mm_aesenclast_si128(s1, rk);
    s2 = _mm_aesenclast_si128(s2, rk);
    s3 = _mm_aesenclast_si128(s3, rk);

    _mm_storeu_si128((__m128i *)(void *)(out + 0U * AES128_BLOCK_SIZE), s0);
    _mm_storeu_si128((__m128i *)(void *)(out + 1U * AES128_BLOCK_SIZE), s1);
    _mm_storeu_si128((__m128i *)(void *)(out + 2U * AES128_BLOCK_SIZE), s2);
    _mm_storeu_si128((__m128i *)(void *)(out + 3U * AES128_BLOCK_SIZE), s3);
}

__attribute__((target("aes,sse2")))
static void decrypt_four_blocks_aesni(
    const aes128_key_t *ctx, const uint8_t *in, uint8_t *out
) {
    __m128i s0 = _mm_loadu_si128((const __m128i *)(const void *)(in + 0U * AES128_BLOCK_SIZE));
    __m128i s1 = _mm_loadu_si128((const __m128i *)(const void *)(in + 1U * AES128_BLOCK_SIZE));
    __m128i s2 = _mm_loadu_si128((const __m128i *)(const void *)(in + 2U * AES128_BLOCK_SIZE));
    __m128i s3 = _mm_loadu_si128((const __m128i *)(const void *)(in + 3U * AES128_BLOCK_SIZE));

    __m128i rk = load_round_key(ctx, AES128_ROUNDS);
    s0 = _mm_xor_si128(s0, rk);
    s1 = _mm_xor_si128(s1, rk);
    s2 = _mm_xor_si128(s2, rk);
    s3 = _mm_xor_si128(s3, rk);

    for (size_t round = AES128_ROUNDS - 1U; round > 0U; --round) {
        rk = _mm_aesimc_si128(load_round_key(ctx, round));
        s0 = _mm_aesdec_si128(s0, rk);
        s1 = _mm_aesdec_si128(s1, rk);
        s2 = _mm_aesdec_si128(s2, rk);
        s3 = _mm_aesdec_si128(s3, rk);
    }

    rk = load_round_key(ctx, 0);
    s0 = _mm_aesdeclast_si128(s0, rk);
    s1 = _mm_aesdeclast_si128(s1, rk);
    s2 = _mm_aesdeclast_si128(s2, rk);
    s3 = _mm_aesdeclast_si128(s3, rk);

    _mm_storeu_si128((__m128i *)(void *)(out + 0U * AES128_BLOCK_SIZE), s0);
    _mm_storeu_si128((__m128i *)(void *)(out + 1U * AES128_BLOCK_SIZE), s1);
    _mm_storeu_si128((__m128i *)(void *)(out + 2U * AES128_BLOCK_SIZE), s2);
    _mm_storeu_si128((__m128i *)(void *)(out + 3U * AES128_BLOCK_SIZE), s3);
}

__attribute__((target("aes,sse2")))
static void encrypt_eight_blocks_aesni(
    const aes128_key_t *ctx, const uint8_t *in, uint8_t *out
) {
    __m128i s0 = _mm_loadu_si128((const __m128i *)(const void *)(in + 0U * AES128_BLOCK_SIZE));
    __m128i s1 = _mm_loadu_si128((const __m128i *)(const void *)(in + 1U * AES128_BLOCK_SIZE));
    __m128i s2 = _mm_loadu_si128((const __m128i *)(const void *)(in + 2U * AES128_BLOCK_SIZE));
    __m128i s3 = _mm_loadu_si128((const __m128i *)(const void *)(in + 3U * AES128_BLOCK_SIZE));
    __m128i s4 = _mm_loadu_si128((const __m128i *)(const void *)(in + 4U * AES128_BLOCK_SIZE));
    __m128i s5 = _mm_loadu_si128((const __m128i *)(const void *)(in + 5U * AES128_BLOCK_SIZE));
    __m128i s6 = _mm_loadu_si128((const __m128i *)(const void *)(in + 6U * AES128_BLOCK_SIZE));
    __m128i s7 = _mm_loadu_si128((const __m128i *)(const void *)(in + 7U * AES128_BLOCK_SIZE));

    __m128i rk = load_round_key(ctx, 0);
    s0 = _mm_xor_si128(s0, rk); s1 = _mm_xor_si128(s1, rk);
    s2 = _mm_xor_si128(s2, rk); s3 = _mm_xor_si128(s3, rk);
    s4 = _mm_xor_si128(s4, rk); s5 = _mm_xor_si128(s5, rk);
    s6 = _mm_xor_si128(s6, rk); s7 = _mm_xor_si128(s7, rk);

    for (size_t round = 1; round < AES128_ROUNDS; ++round) {
        rk = load_round_key(ctx, round);
        s0 = _mm_aesenc_si128(s0, rk); s1 = _mm_aesenc_si128(s1, rk);
        s2 = _mm_aesenc_si128(s2, rk); s3 = _mm_aesenc_si128(s3, rk);
        s4 = _mm_aesenc_si128(s4, rk); s5 = _mm_aesenc_si128(s5, rk);
        s6 = _mm_aesenc_si128(s6, rk); s7 = _mm_aesenc_si128(s7, rk);
    }

    rk = load_round_key(ctx, AES128_ROUNDS);
    s0 = _mm_aesenclast_si128(s0, rk); s1 = _mm_aesenclast_si128(s1, rk);
    s2 = _mm_aesenclast_si128(s2, rk); s3 = _mm_aesenclast_si128(s3, rk);
    s4 = _mm_aesenclast_si128(s4, rk); s5 = _mm_aesenclast_si128(s5, rk);
    s6 = _mm_aesenclast_si128(s6, rk); s7 = _mm_aesenclast_si128(s7, rk);

    _mm_storeu_si128((__m128i *)(void *)(out + 0U * AES128_BLOCK_SIZE), s0);
    _mm_storeu_si128((__m128i *)(void *)(out + 1U * AES128_BLOCK_SIZE), s1);
    _mm_storeu_si128((__m128i *)(void *)(out + 2U * AES128_BLOCK_SIZE), s2);
    _mm_storeu_si128((__m128i *)(void *)(out + 3U * AES128_BLOCK_SIZE), s3);
    _mm_storeu_si128((__m128i *)(void *)(out + 4U * AES128_BLOCK_SIZE), s4);
    _mm_storeu_si128((__m128i *)(void *)(out + 5U * AES128_BLOCK_SIZE), s5);
    _mm_storeu_si128((__m128i *)(void *)(out + 6U * AES128_BLOCK_SIZE), s6);
    _mm_storeu_si128((__m128i *)(void *)(out + 7U * AES128_BLOCK_SIZE), s7);
}

__attribute__((target("aes,sse2")))
static void decrypt_eight_blocks_aesni(
    const aes128_key_t *ctx, const uint8_t *in, uint8_t *out
) {
    __m128i s0 = _mm_loadu_si128((const __m128i *)(const void *)(in + 0U * AES128_BLOCK_SIZE));
    __m128i s1 = _mm_loadu_si128((const __m128i *)(const void *)(in + 1U * AES128_BLOCK_SIZE));
    __m128i s2 = _mm_loadu_si128((const __m128i *)(const void *)(in + 2U * AES128_BLOCK_SIZE));
    __m128i s3 = _mm_loadu_si128((const __m128i *)(const void *)(in + 3U * AES128_BLOCK_SIZE));
    __m128i s4 = _mm_loadu_si128((const __m128i *)(const void *)(in + 4U * AES128_BLOCK_SIZE));
    __m128i s5 = _mm_loadu_si128((const __m128i *)(const void *)(in + 5U * AES128_BLOCK_SIZE));
    __m128i s6 = _mm_loadu_si128((const __m128i *)(const void *)(in + 6U * AES128_BLOCK_SIZE));
    __m128i s7 = _mm_loadu_si128((const __m128i *)(const void *)(in + 7U * AES128_BLOCK_SIZE));

    __m128i rk = load_round_key(ctx, AES128_ROUNDS);
    s0 = _mm_xor_si128(s0, rk); s1 = _mm_xor_si128(s1, rk);
    s2 = _mm_xor_si128(s2, rk); s3 = _mm_xor_si128(s3, rk);
    s4 = _mm_xor_si128(s4, rk); s5 = _mm_xor_si128(s5, rk);
    s6 = _mm_xor_si128(s6, rk); s7 = _mm_xor_si128(s7, rk);

    for (size_t round = AES128_ROUNDS - 1U; round > 0U; --round) {
        rk = _mm_aesimc_si128(load_round_key(ctx, round));
        s0 = _mm_aesdec_si128(s0, rk); s1 = _mm_aesdec_si128(s1, rk);
        s2 = _mm_aesdec_si128(s2, rk); s3 = _mm_aesdec_si128(s3, rk);
        s4 = _mm_aesdec_si128(s4, rk); s5 = _mm_aesdec_si128(s5, rk);
        s6 = _mm_aesdec_si128(s6, rk); s7 = _mm_aesdec_si128(s7, rk);
    }

    rk = load_round_key(ctx, 0);
    s0 = _mm_aesdeclast_si128(s0, rk); s1 = _mm_aesdeclast_si128(s1, rk);
    s2 = _mm_aesdeclast_si128(s2, rk); s3 = _mm_aesdeclast_si128(s3, rk);
    s4 = _mm_aesdeclast_si128(s4, rk); s5 = _mm_aesdeclast_si128(s5, rk);
    s6 = _mm_aesdeclast_si128(s6, rk); s7 = _mm_aesdeclast_si128(s7, rk);

    _mm_storeu_si128((__m128i *)(void *)(out + 0U * AES128_BLOCK_SIZE), s0);
    _mm_storeu_si128((__m128i *)(void *)(out + 1U * AES128_BLOCK_SIZE), s1);
    _mm_storeu_si128((__m128i *)(void *)(out + 2U * AES128_BLOCK_SIZE), s2);
    _mm_storeu_si128((__m128i *)(void *)(out + 3U * AES128_BLOCK_SIZE), s3);
    _mm_storeu_si128((__m128i *)(void *)(out + 4U * AES128_BLOCK_SIZE), s4);
    _mm_storeu_si128((__m128i *)(void *)(out + 5U * AES128_BLOCK_SIZE), s5);
    _mm_storeu_si128((__m128i *)(void *)(out + 6U * AES128_BLOCK_SIZE), s6);
    _mm_storeu_si128((__m128i *)(void *)(out + 7U * AES128_BLOCK_SIZE), s7);
}
#endif

int aes128_aesni_supported(void) {
#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
    __builtin_cpu_init();
    return __builtin_cpu_supports("aes") != 0;
#else
    return 0;
#endif
}

void aes128_encrypt_block_aesni(
    const aes128_key_t *ctx,
    const uint8_t in[AES128_BLOCK_SIZE],
    uint8_t out[AES128_BLOCK_SIZE]
) {
#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
    if (aes128_aesni_supported()) {
        encrypt_one_block_aesni(ctx, in, out);
        return;
    }
#endif
    aes128_encrypt_block_ttable(ctx, in, out);
}

void aes128_decrypt_block_aesni(
    const aes128_key_t *ctx,
    const uint8_t in[AES128_BLOCK_SIZE],
    uint8_t out[AES128_BLOCK_SIZE]
) {
#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
    if (aes128_aesni_supported()) {
        decrypt_one_block_aesni(ctx, in, out);
        return;
    }
#endif
    aes128_decrypt_block_ref(ctx, in, out);
}

void aes128_encrypt_blocks_aesni(
    const aes128_key_t *ctx,
    const uint8_t *in,
    uint8_t *out,
    size_t blocks
) {
#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
    if (aes128_aesni_supported()) {
        while (blocks >= 8U) {
            encrypt_eight_blocks_aesni(ctx, in, out);
            in += 8U * AES128_BLOCK_SIZE;
            out += 8U * AES128_BLOCK_SIZE;
            blocks -= 8U;
        }
        if (blocks >= 4U) {
            encrypt_four_blocks_aesni(ctx, in, out);
            in += 4U * AES128_BLOCK_SIZE;
            out += 4U * AES128_BLOCK_SIZE;
            blocks -= 4U;
        }
        while (blocks != 0U) {
            encrypt_one_block_aesni(ctx, in, out);
            in += AES128_BLOCK_SIZE;
            out += AES128_BLOCK_SIZE;
            --blocks;
        }
        return;
    }
#endif
    aes128_encrypt_blocks_ttable(ctx, in, out, blocks);
}

void aes128_decrypt_blocks_aesni(
    const aes128_key_t *ctx,
    const uint8_t *in,
    uint8_t *out,
    size_t blocks
) {
#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
    if (aes128_aesni_supported()) {
        while (blocks >= 8U) {
            decrypt_eight_blocks_aesni(ctx, in, out);
            in += 8U * AES128_BLOCK_SIZE;
            out += 8U * AES128_BLOCK_SIZE;
            blocks -= 8U;
        }
        if (blocks >= 4U) {
            decrypt_four_blocks_aesni(ctx, in, out);
            in += 4U * AES128_BLOCK_SIZE;
            out += 4U * AES128_BLOCK_SIZE;
            blocks -= 4U;
        }
        while (blocks != 0U) {
            decrypt_one_block_aesni(ctx, in, out);
            in += AES128_BLOCK_SIZE;
            out += AES128_BLOCK_SIZE;
            --blocks;
        }
        return;
    }
#endif
    aes128_decrypt_blocks_ref(ctx, in, out, blocks);
}
