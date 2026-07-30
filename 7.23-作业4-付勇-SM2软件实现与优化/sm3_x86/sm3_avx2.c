#include "sm3_x86.h"

#include <immintrin.h>
#include <limits.h>
#include <string.h>

#define VADD(a,b) _mm256_add_epi32((a),(b))
#define VXOR(a,b) _mm256_xor_si256((a),(b))
#define VAND(a,b) _mm256_and_si256((a),(b))
#define VOR(a,b)  _mm256_or_si256((a),(b))
#define VROL(x,n) VOR(_mm256_slli_epi32((x),(n)), _mm256_srli_epi32((x),32-(n)))

static const uint32_t SM3_IV[8] = {
    UINT32_C(0x7380166F), UINT32_C(0x4914B2B9),
    UINT32_C(0x172442D7), UINT32_C(0xDA8A0600),
    UINT32_C(0xA96F30BC), UINT32_C(0x163138AA),
    UINT32_C(0xE38DEE4D), UINT32_C(0xB0FB0E4E)
};

static inline uint32_t rotl32_scalar(uint32_t x, unsigned n)
{
    n &= 31U;
    return n == 0U ? x : (x << n) | (x >> (32U - n));
}

static inline uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24U)
         | ((uint32_t)p[1] << 16U)
         | ((uint32_t)p[2] << 8U)
         | (uint32_t)p[3];
}

static inline void store_be32(uint8_t *p, uint32_t x)
{
    p[0] = (uint8_t)(x >> 24U);
    p[1] = (uint8_t)(x >> 16U);
    p[2] = (uint8_t)(x >> 8U);
    p[3] = (uint8_t)x;
}

static inline void store_be64(uint8_t *p, uint64_t x)
{
    for (int i = 7; i >= 0; --i) {
        p[i] = (uint8_t)x;
        x >>= 8U;
    }
}

static inline __m256i vp0(__m256i x)
{
    return VXOR(VXOR(x, VROL(x, 9)), VROL(x, 17));
}

static inline __m256i vp1(__m256i x)
{
    return VXOR(VXOR(x, VROL(x, 15)), VROL(x, 23));
}

static inline __m256i vff0(__m256i x, __m256i y, __m256i z)
{
    return VXOR(VXOR(x, y), z);
}

static inline __m256i vff1(__m256i x, __m256i y, __m256i z)
{
    return VOR(VOR(VAND(x, y), VAND(x, z)), VAND(y, z));
}

static inline __m256i vgg1(__m256i x, __m256i y, __m256i z)
{
    const __m256i ones = _mm256_set1_epi32(-1);
    return VOR(VAND(x, y), VAND(VXOR(x, ones), z));
}

static inline __m256i lane_mask8(unsigned active)
{
    return _mm256_set_epi32(
        (active & 0x80U) ? -1 : 0,
        (active & 0x40U) ? -1 : 0,
        (active & 0x20U) ? -1 : 0,
        (active & 0x10U) ? -1 : 0,
        (active & 0x08U) ? -1 : 0,
        (active & 0x04U) ? -1 : 0,
        (active & 0x02U) ? -1 : 0,
        (active & 0x01U) ? -1 : 0);
}

static inline __m256i load_word8(const uint8_t *const blocks[8], unsigned word)
{
    const size_t off = (size_t)word * 4U;
    return _mm256_set_epi32(
        (int)load_be32(blocks[7] + off),
        (int)load_be32(blocks[6] + off),
        (int)load_be32(blocks[5] + off),
        (int)load_be32(blocks[4] + off),
        (int)load_be32(blocks[3] + off),
        (int)load_be32(blocks[2] + off),
        (int)load_be32(blocks[1] + off),
        (int)load_be32(blocks[0] + off));
}

static void sm3_compress8(__m256i state[8],
                          const uint8_t *const blocks[8],
                          unsigned active)
{
    __m256i w[68];
    __m256i wp[64];
    __m256i a, b, c, d, e, f, g, h;

    for (unsigned j = 0; j < 16U; ++j) {
        w[j] = load_word8(blocks, j);
    }
    for (unsigned j = 16U; j < 68U; ++j) {
        const __m256i x = VXOR(VXOR(w[j - 16U], w[j - 9U]),
                                VROL(w[j - 3U], 15));
        w[j] = VXOR(VXOR(vp1(x), VROL(w[j - 13U], 7)), w[j - 6U]);
    }
    for (unsigned j = 0; j < 64U; ++j) {
        wp[j] = VXOR(w[j], w[j + 4U]);
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (unsigned j = 0; j < 64U; ++j) {
        const uint32_t t = j < 16U ? UINT32_C(0x79CC4519)
                                   : UINT32_C(0x7A879D8A);
        const __m256i tj = _mm256_set1_epi32((int)rotl32_scalar(t, j));
        const __m256i a12 = VROL(a, 12);
        const __m256i ss1 = VROL(VADD(VADD(a12, e), tj), 7);
        const __m256i ss2 = VXOR(ss1, a12);
        const __m256i ff = j < 16U ? vff0(a, b, c) : vff1(a, b, c);
        const __m256i gg = j < 16U ? vff0(e, f, g) : vgg1(e, f, g);
        const __m256i tt1 = VADD(VADD(VADD(ff, d), ss2), wp[j]);
        const __m256i tt2 = VADD(VADD(VADD(gg, h), ss1), w[j]);

        d = c;
        c = VROL(b, 9);
        b = a;
        a = tt1;
        h = g;
        g = VROL(f, 19);
        f = e;
        e = vp0(tt2);
    }

    const __m256i next[8] = {
        VXOR(state[0], a), VXOR(state[1], b),
        VXOR(state[2], c), VXOR(state[3], d),
        VXOR(state[4], e), VXOR(state[5], f),
        VXOR(state[6], g), VXOR(state[7], h)
    };

    if ((active & 0xFFU) == 0xFFU) {
        for (unsigned i = 0; i < 8U; ++i) {
            state[i] = next[i];
        }
    } else {
        const __m256i mask = lane_mask8(active);
        for (unsigned i = 0; i < 8U; ++i) {
            state[i] = _mm256_blendv_epi8(state[i], next[i], mask);
        }
    }
}

int sm3_hash8_avx2(const uint8_t *messages[8],
                   const size_t lengths[8],
                   uint8_t digests[8][SM3_DIGEST_SIZE])
{
    __m256i state[8];
    size_t full_blocks[8];
    size_t max_full = 0U;
    static const uint8_t zero_block[SM3_BLOCK_SIZE] = {0};
    const uint8_t *blocks[8];
    uint8_t tail1[8][SM3_BLOCK_SIZE];
    uint8_t tail2[8][SM3_BLOCK_SIZE];
    unsigned second_mask = 0U;

    if (messages == NULL || lengths == NULL || digests == NULL) {
        return -1;
    }
    for (unsigned lane = 0; lane < 8U; ++lane) {
        if (messages[lane] == NULL && lengths[lane] != 0U) {
            return -1;
        }
        if (lengths[lane] > UINT64_MAX / 8U) {
            return -1;
        }
        full_blocks[lane] = lengths[lane] / SM3_BLOCK_SIZE;
        if (full_blocks[lane] > max_full) {
            max_full = full_blocks[lane];
        }
    }

    for (unsigned i = 0; i < 8U; ++i) {
        state[i] = _mm256_set1_epi32((int)SM3_IV[i]);
    }

    for (size_t block_index = 0; block_index < max_full; ++block_index) {
        unsigned active = 0U;
        for (unsigned lane = 0; lane < 8U; ++lane) {
            if (block_index < full_blocks[lane]) {
                blocks[lane] = messages[lane] + block_index * SM3_BLOCK_SIZE;
                active |= 1U << lane;
            } else {
                blocks[lane] = zero_block;
            }
        }
        sm3_compress8(state, blocks, active);
    }

    memset(tail1, 0, sizeof(tail1));
    memset(tail2, 0, sizeof(tail2));
    for (unsigned lane = 0; lane < 8U; ++lane) {
        const size_t rem = lengths[lane] % SM3_BLOCK_SIZE;
        const uint8_t *src = messages[lane] == NULL
                           ? zero_block
                           : messages[lane] + full_blocks[lane] * SM3_BLOCK_SIZE;
        if (rem != 0U) {
            memcpy(tail1[lane], src, rem);
        }
        tail1[lane][rem] = UINT8_C(0x80);
        if (rem <= 55U) {
            store_be64(tail1[lane] + 56U, (uint64_t)lengths[lane] * 8U);
        } else {
            store_be64(tail2[lane] + 56U, (uint64_t)lengths[lane] * 8U);
            second_mask |= 1U << lane;
        }
        blocks[lane] = tail1[lane];
    }
    sm3_compress8(state, blocks, 0xFFU);

    if (second_mask != 0U) {
        for (unsigned lane = 0; lane < 8U; ++lane) {
            blocks[lane] = tail2[lane];
        }
        sm3_compress8(state, blocks, second_mask);
    }

    for (unsigned word = 0; word < 8U; ++word) {
        uint32_t values[8];
        _mm256_storeu_si256((__m256i *)(void *)values, state[word]);
        for (unsigned lane = 0; lane < 8U; ++lane) {
            store_be32(digests[lane] + 4U * word, values[lane]);
        }
    }
    _mm256_zeroupper();
    return 0;
}
