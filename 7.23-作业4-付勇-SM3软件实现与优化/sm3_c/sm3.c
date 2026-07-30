#include "sm3.h"
#include "sm3_internal.h"

#include <string.h>

#if defined(SM3_USE_ARM64_ASM) && defined(SM3_USE_ARM64_NEON)
#error "Only one ARM64 SM3 backend may be enabled"
#endif

#if defined(SM3_USE_ARM64_ASM)

#if !defined(__aarch64__)
#error "SM3_USE_ARM64_ASM requires an AArch64 target"
#endif

#define SM3_COMPRESS_BLOCK sm3_compress_arm64_asm

#elif defined(SM3_USE_ARM64_NEON)

#if !defined(__aarch64__)
#error "SM3_USE_ARM64_NEON requires an AArch64 target"
#endif

#define SM3_COMPRESS_BLOCK sm3_compress_arm64_neon

#else

#define SM3_COMPRESS_BLOCK sm3_compress_ref

#endif

static inline uint32_t rotl32(uint32_t x, unsigned int n)
{
    n &= 31U;

    if (n == 0U) {
        return x;
    }

    return (x << n) | (x >> (32U - n));
}

static inline uint32_t sm3_p0(uint32_t x)
{
    return x
         ^ rotl32(x, 9U)
         ^ rotl32(x, 17U);
}

static inline uint32_t sm3_p1(uint32_t x)
{
    return x
         ^ rotl32(x, 15U)
         ^ rotl32(x, 23U);
}

static inline uint32_t sm3_ff(uint32_t x,
                              uint32_t y,
                              uint32_t z,
                              unsigned int round)
{
    if (round < 16U) {
        return x ^ y ^ z;
    }

    return (x & y)
         | (x & z)
         | (y & z);
}

static inline uint32_t sm3_gg(uint32_t x,
                              uint32_t y,
                              uint32_t z,
                              unsigned int round)
{
    if (round < 16U) {
        return x ^ y ^ z;
    }

    return (x & y)
         | ((~x) & z);
}

static inline uint32_t load_be32(const uint8_t input[4])
{
    return ((uint32_t)input[0] << 24U)
         | ((uint32_t)input[1] << 16U)
         | ((uint32_t)input[2] << 8U)
         | ((uint32_t)input[3]);
}

static inline void store_be32(uint8_t output[4], uint32_t value)
{
    output[0] = (uint8_t)(value >> 24U);
    output[1] = (uint8_t)(value >> 16U);
    output[2] = (uint8_t)(value >> 8U);
    output[3] = (uint8_t)value;
}

static inline void store_be64(uint8_t output[8], uint64_t value)
{
    output[0] = (uint8_t)(value >> 56U);
    output[1] = (uint8_t)(value >> 48U);
    output[2] = (uint8_t)(value >> 40U);
    output[3] = (uint8_t)(value >> 32U);
    output[4] = (uint8_t)(value >> 24U);
    output[5] = (uint8_t)(value >> 16U);
    output[6] = (uint8_t)(value >> 8U);
    output[7] = (uint8_t)value;
}

void sm3_compress_ref(
    uint32_t state[SM3_STATE_WORDS],
    const uint8_t block[SM3_BLOCK_SIZE])
{
    uint32_t w[68];
    uint32_t w1[64];

    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g;
    uint32_t h;

    unsigned int j;

    for (j = 0U; j < 16U; ++j) {
        w[j] = load_be32(block + 4U * j);
    }

    for (j = 16U; j < 68U; ++j) {
        const uint32_t x =
            w[j - 16U]
            ^ w[j - 9U]
            ^ rotl32(w[j - 3U], 15U);

        w[j] =
            sm3_p1(x)
            ^ rotl32(w[j - 13U], 7U)
            ^ w[j - 6U];
    }

    for (j = 0U; j < 64U; ++j) {
        w1[j] = w[j] ^ w[j + 4U];
    }

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];

    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    for (j = 0U; j < 64U; ++j) {
        const uint32_t tj =
            (j < 16U)
            ? UINT32_C(0x79CC4519)
            : UINT32_C(0x7A879D8A);

        const uint32_t a12 =
            rotl32(a, 12U);

        const uint32_t ss1 =
            rotl32(
                a12
                + e
                + rotl32(tj, j),
                7U);

        const uint32_t ss2 =
            ss1 ^ a12;

        const uint32_t tt1 =
            sm3_ff(a, b, c, j)
            + d
            + ss2
            + w1[j];

        const uint32_t tt2 =
            sm3_gg(e, f, g, j)
            + h
            + ss1
            + w[j];

        d = c;
        c = rotl32(b, 9U);
        b = a;
        a = tt1;

        h = g;
        g = rotl32(f, 19U);
        f = e;
        e = sm3_p0(tt2);
    }

    state[0] ^= a;
    state[1] ^= b;
    state[2] ^= c;
    state[3] ^= d;

    state[4] ^= e;
    state[5] ^= f;
    state[6] ^= g;
    state[7] ^= h;
}

void sm3_init(sm3_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    ctx->state[0] = UINT32_C(0x7380166F);
    ctx->state[1] = UINT32_C(0x4914B2B9);
    ctx->state[2] = UINT32_C(0x172442D7);
    ctx->state[3] = UINT32_C(0xDA8A0600);
    ctx->state[4] = UINT32_C(0xA96F30BC);
    ctx->state[5] = UINT32_C(0x163138AA);
    ctx->state[6] = UINT32_C(0xE38DEE4D);
    ctx->state[7] = UINT32_C(0xB0FB0E4E);

    ctx->total_bytes = UINT64_C(0);
    ctx->buffer_len = 0U;

    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

void sm3_update(sm3_ctx *ctx,
                const uint8_t *data,
                size_t len)
{
    size_t copy_len;

    if (ctx == NULL) {
        return;
    }

    if (data == NULL) {
        return;
    }

    if (len == 0U) {
        return;
    }

    ctx->total_bytes += (uint64_t)len;

    if (ctx->buffer_len != 0U) {
        copy_len =
            SM3_BLOCK_SIZE - ctx->buffer_len;

        if (copy_len > len) {
            copy_len = len;
        }

        memcpy(
            ctx->buffer + ctx->buffer_len,
            data,
            copy_len);

        ctx->buffer_len += copy_len;
        data += copy_len;
        len -= copy_len;

        if (ctx->buffer_len == SM3_BLOCK_SIZE) {
            SM3_COMPRESS_BLOCK(
                ctx->state,
                ctx->buffer);

            ctx->buffer_len = 0U;
        }
    }

    while (len >= SM3_BLOCK_SIZE) {
        SM3_COMPRESS_BLOCK(
            ctx->state,
            data);

        data += SM3_BLOCK_SIZE;
        len -= SM3_BLOCK_SIZE;
    }

    if (len != 0U) {
        memcpy(ctx->buffer, data, len);
        ctx->buffer_len = len;
    }
}

void sm3_final(sm3_ctx *ctx,
               uint8_t digest[SM3_DIGEST_SIZE])
{
    uint64_t total_bits;
    size_t i;

    if (ctx == NULL || digest == NULL) {
        return;
    }

    total_bits =
        ctx->total_bytes << 3U;

    ctx->buffer[ctx->buffer_len++] =
        UINT8_C(0x80);

    if (ctx->buffer_len > 56U) {
        memset(
            ctx->buffer + ctx->buffer_len,
            0,
            SM3_BLOCK_SIZE - ctx->buffer_len);

        SM3_COMPRESS_BLOCK(
            ctx->state,
            ctx->buffer);

        ctx->buffer_len = 0U;
    }

    memset(
        ctx->buffer + ctx->buffer_len,
        0,
        56U - ctx->buffer_len);

    store_be64(
        ctx->buffer + 56U,
        total_bits);

    SM3_COMPRESS_BLOCK(
        ctx->state,
        ctx->buffer);

    for (i = 0U;
         i < SM3_STATE_WORDS;
         ++i) {
        store_be32(
            digest + 4U * i,
            ctx->state[i]);
    }

    ctx->buffer_len = 0U;

    memset(
        ctx->buffer,
        0,
        sizeof(ctx->buffer));
}

void sm3_digest(const uint8_t *data,
                size_t len,
                uint8_t digest[SM3_DIGEST_SIZE])
{
    sm3_ctx ctx;

    if (digest == NULL) {
        return;
    }

    if (data == NULL && len != 0U) {
        return;
    }

    sm3_init(&ctx);
    sm3_update(&ctx, data, len);
    sm3_final(&ctx, digest);
}

#undef SM3_COMPRESS_BLOCK