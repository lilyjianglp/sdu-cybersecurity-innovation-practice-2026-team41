

#include "sm3_internal.h"

#if !defined(__aarch64__)
#error "sm3_arm64_neon.c must be compiled for AArch64"
#endif

#include <arm_neon.h>
#include <stdint.h>

static inline uint32_t rotl32_scalar(uint32_t x, unsigned int n)
{
    n &= 31U;

    if (n == 0U) {
        return x;
    }

    return (x << n) | (x >> (32U - n));
}


static inline uint32_t p0_scalar(uint32_t x)
{
    return x
         ^ rotl32_scalar(x, 9U)
         ^ rotl32_scalar(x, 17U);
}


static inline uint32_t p1_scalar(uint32_t x)
{
    return x
         ^ rotl32_scalar(x, 15U)
         ^ rotl32_scalar(x, 23U);
}


#define SM3_EXPAND_WORD(J)                                        \
    do {                                                          \
        const uint32_t sm3_x =                                    \
            w[(J) - 16U]                                          \
            ^ w[(J) - 9U]                                        \
            ^ rotl32_scalar(w[(J) - 3U], 15U);                    \
                                                                    \
        w[(J)] =                                                  \
            p1_scalar(sm3_x)                                      \
            ^ rotl32_scalar(w[(J) - 13U], 7U)                     \
            ^ w[(J) - 6U];                                       \
    } while (0)


#define SM3_ROUND_0_15(A, B, C, D, E, F, G, H, J, T)             \
    do {                                                          \
        const uint32_t sm3_a12 =                                  \
            rotl32_scalar((A), 12U);                              \
                                                                    \
        const uint32_t sm3_ss1 =                                  \
            rotl32_scalar(                                        \
                sm3_a12 + (E) + (T),                              \
                7U);                                               \
                                                                    \
        const uint32_t sm3_ss2 = sm3_ss1 ^ sm3_a12;               \
                                                                    \
        (D) += ((A) ^ (B) ^ (C))                                  \
             + sm3_ss2                                             \
             + wp[(J)];                                            \
                                                                    \
        (H) += ((E) ^ (F) ^ (G))                                  \
             + sm3_ss1                                             \
             + w[(J)];                                             \
                                                                    \
        (B) = rotl32_scalar((B), 9U);                             \
        (F) = rotl32_scalar((F), 19U);                            \
        (H) = p0_scalar((H));                                     \
    } while (0)


#define SM3_ROUND_16_63(A, B, C, D, E, F, G, H, J, T)            \
    do {                                                          \
        const uint32_t sm3_a12 =                                  \
            rotl32_scalar((A), 12U);                              \
                                                                    \
        const uint32_t sm3_ss1 =                                  \
            rotl32_scalar(                                        \
                sm3_a12 + (E) + (T),                              \
                7U);                                               \
                                                                    \
        const uint32_t sm3_ss2 = sm3_ss1 ^ sm3_a12;               \
                                                                    \
        const uint32_t sm3_ff =                                   \
            ((A) & (B))                                           \
          | ((A) & (C))                                           \
          | ((B) & (C));                                          \
                                                                    \
        const uint32_t sm3_gg =                                   \
            ((E) & (F))                                           \
          | ((~(E)) & (G));                                       \
                                                                    \
        (D) += sm3_ff                                             \
             + sm3_ss2                                             \
             + wp[(J)];                                            \
                                                                    \
        (H) += sm3_gg                                             \
             + sm3_ss1                                             \
             + w[(J)];                                             \
                                                                    \
        (B) = rotl32_scalar((B), 9U);                             \
        (F) = rotl32_scalar((F), 19U);                            \
        (H) = p0_scalar((H));                                     \
    } while (0)


void sm3_compress_arm64_neon(
    uint32_t state[SM3_STATE_WORDS],
    const uint8_t block[SM3_BLOCK_SIZE])
{
    
    _Alignas(16) uint32_t w[68];

    
    _Alignas(16) uint32_t wp[64];

    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g;
    uint32_t h;

    uint32_t round_constant;
    unsigned int j;

    
    const uint32x4_t m0 =
        vreinterpretq_u32_u8(
            vrev32q_u8(
                vld1q_u8(block + 0U)));

    const uint32x4_t m1 =
        vreinterpretq_u32_u8(
            vrev32q_u8(
                vld1q_u8(block + 16U)));

    const uint32x4_t m2 =
        vreinterpretq_u32_u8(
            vrev32q_u8(
                vld1q_u8(block + 32U)));

    const uint32x4_t m3 =
        vreinterpretq_u32_u8(
            vrev32q_u8(
                vld1q_u8(block + 48U)));

    
    vst1q_u32(&w[0], m0);
    vst1q_u32(&w[4], m1);
    vst1q_u32(&w[8], m2);
    vst1q_u32(&w[12], m3);

    
    /*
     * Consecutive SM3 schedule words are not fully independent:
     * W[j + 3] depends on the newly generated W[j].  Computing four
     * consecutive words as four NEON lanes therefore creates a false
     * fourth lane that has to be recomputed.  Keep this recurrence in
     * general-purpose registers, where AArch64 has single-instruction
     * rotates, and reserve NEON for genuinely independent operations.
     */
    for (j = 16U; j < 68U; j += 4U) {
        SM3_EXPAND_WORD(j);
        SM3_EXPAND_WORD(j + 1U);
        SM3_EXPAND_WORD(j + 2U);
        SM3_EXPAND_WORD(j + 3U);
    }

   
    for (j = 0U; j < 64U; j += 4U) {
        const uint32x4_t x =
            vld1q_u32(&w[j]);

        const uint32x4_t y =
            vld1q_u32(&w[j + 4U]);

        vst1q_u32(
            &wp[j],
            veorq_u32(x, y));
    }

    
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];

    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

   
    round_constant = UINT32_C(0x79CC4519);

    for (j = 0U; j < 16U; j += 4U) {
        SM3_ROUND_0_15(
            a, b, c, d,
            e, f, g, h,
            j,
            round_constant);

        round_constant =
            rotl32_scalar(round_constant, 1U);

        SM3_ROUND_0_15(
            d, a, b, c,
            h, e, f, g,
            j + 1U,
            round_constant);

        round_constant =
            rotl32_scalar(round_constant, 1U);

        SM3_ROUND_0_15(
            c, d, a, b,
            g, h, e, f,
            j + 2U,
            round_constant);

        round_constant =
            rotl32_scalar(round_constant, 1U);

        SM3_ROUND_0_15(
            b, c, d, a,
            f, g, h, e,
            j + 3U,
            round_constant);

        round_constant =
            rotl32_scalar(round_constant, 1U);
    }

    
    round_constant =
        rotl32_scalar(
            UINT32_C(0x7A879D8A),
            16U);

   
    for (j = 16U; j < 64U; j += 4U) {
        SM3_ROUND_16_63(
            a, b, c, d,
            e, f, g, h,
            j,
            round_constant);

        round_constant =
            rotl32_scalar(round_constant, 1U);

        SM3_ROUND_16_63(
            d, a, b, c,
            h, e, f, g,
            j + 1U,
            round_constant);

        round_constant =
            rotl32_scalar(round_constant, 1U);

        SM3_ROUND_16_63(
            c, d, a, b,
            g, h, e, f,
            j + 2U,
            round_constant);

        round_constant =
            rotl32_scalar(round_constant, 1U);

        SM3_ROUND_16_63(
            b, c, d, a,
            f, g, h, e,
            j + 3U,
            round_constant);

        round_constant =
            rotl32_scalar(round_constant, 1U);
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

#undef SM3_EXPAND_WORD
#undef SM3_ROUND_0_15
#undef SM3_ROUND_16_63
