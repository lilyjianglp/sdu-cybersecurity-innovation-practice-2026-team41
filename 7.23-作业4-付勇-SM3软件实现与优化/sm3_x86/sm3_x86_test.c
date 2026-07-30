#include "sm3_x86.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LEN 8192U
#define RANDOM_ROUNDS 300U

static uint64_t rng_state = UINT64_C(0x8f3d9a21c67b4e55);

static uint32_t prng32(void)
{
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return (uint32_t)(x >> 16);
}

static void fill_random(uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        buf[i] = (uint8_t)prng32();
    }
}

static void print_hex(const uint8_t digest[32])
{
    for (unsigned i = 0; i < 32U; ++i) {
        printf("%02x", digest[i]);
    }
}

static int check_abc(void)
{
    static const uint8_t expected[32] = {
        0x66,0xc7,0xf0,0xf4,0x62,0xee,0xed,0xd9,
        0xd1,0xf2,0xd4,0x6b,0xdc,0x10,0xe4,0xe2,
        0x41,0x67,0xc4,0x87,0x5c,0xf2,0xf7,0xa2,
        0x29,0x7d,0xa0,0x2b,0x8f,0x4b,0xa8,0xe0
    };
    uint8_t got[32];
    sm3_digest((const uint8_t *)"abc", 3U, got);
    if (memcmp(got, expected, 32U) != 0) {
        fprintf(stderr, "scalar abc failed\nexpected: ");
        print_hex(expected);
        fprintf(stderr, "\ngot:      ");
        print_hex(got);
        fprintf(stderr, "\n");
        return -1;
    }
    return 0;
}

static int test_avx2_edges(void)
{
    static const size_t edges[8] = {0U, 1U, 55U, 56U, 63U, 64U, 65U, 8192U};
    uint8_t *buf[8] = {0};
    const uint8_t *msg[8];
    uint8_t got[8][32];
    uint8_t ref[32];

    for (unsigned i = 0; i < 8U; ++i) {
        buf[i] = malloc(edges[i] == 0U ? 1U : edges[i]);
        if (buf[i] == NULL) return -1;
        fill_random(buf[i], edges[i]);
        msg[i] = buf[i];
    }
    if (sm3_hash8_avx2(msg, edges, got) != 0) return -1;
    for (unsigned i = 0; i < 8U; ++i) {
        sm3_digest(msg[i], edges[i], ref);
        if (memcmp(ref, got[i], 32U) != 0) {
            fprintf(stderr, "AVX2 edge mismatch lane=%u len=%zu\n", i, edges[i]);
            return -1;
        }
    }
    for (unsigned i = 0; i < 8U; ++i) free(buf[i]);
    return 0;
}

static int test_avx512_edges(void)
{
    static const size_t edges[16] = {
        0U,1U,2U,3U,54U,55U,56U,57U,
        62U,63U,64U,65U,119U,120U,121U,8192U
    };
    uint8_t *buf[16] = {0};
    const uint8_t *msg[16];
    uint8_t got[16][32];
    uint8_t ref[32];

    for (unsigned i = 0; i < 16U; ++i) {
        buf[i] = malloc(edges[i] == 0U ? 1U : edges[i]);
        if (buf[i] == NULL) return -1;
        fill_random(buf[i], edges[i]);
        msg[i] = buf[i];
    }
    if (sm3_hash16_avx512(msg, edges, got) != 0) return -1;
    for (unsigned i = 0; i < 16U; ++i) {
        sm3_digest(msg[i], edges[i], ref);
        if (memcmp(ref, got[i], 32U) != 0) {
            fprintf(stderr, "AVX-512 edge mismatch lane=%u len=%zu\n", i, edges[i]);
            return -1;
        }
    }
    for (unsigned i = 0; i < 16U; ++i) free(buf[i]);
    return 0;
}

static int test_random_avx2(void)
{
    uint8_t *buf[8] = {0};
    const uint8_t *msg[8];
    size_t len[8];
    uint8_t got[8][32];
    uint8_t ref[32];

    for (unsigned i = 0; i < 8U; ++i) {
        buf[i] = malloc(MAX_LEN);
        if (buf[i] == NULL) return -1;
        msg[i] = buf[i];
    }
    for (unsigned round = 0; round < RANDOM_ROUNDS; ++round) {
        for (unsigned lane = 0; lane < 8U; ++lane) {
            len[lane] = (size_t)(prng32() % (MAX_LEN + 1U));
            fill_random(buf[lane], len[lane]);
        }
        if (sm3_hash8_avx2(msg, len, got) != 0) return -1;
        for (unsigned lane = 0; lane < 8U; ++lane) {
            sm3_digest(msg[lane], len[lane], ref);
            if (memcmp(ref, got[lane], 32U) != 0) {
                fprintf(stderr, "AVX2 random mismatch round=%u lane=%u len=%zu\n",
                        round, lane, len[lane]);
                return -1;
            }
        }
    }
    for (unsigned i = 0; i < 8U; ++i) free(buf[i]);
    return 0;
}

static int test_random_avx512(void)
{
    uint8_t *buf[16] = {0};
    const uint8_t *msg[16];
    size_t len[16];
    uint8_t got[16][32];
    uint8_t ref[32];

    for (unsigned i = 0; i < 16U; ++i) {
        buf[i] = malloc(MAX_LEN);
        if (buf[i] == NULL) return -1;
        msg[i] = buf[i];
    }
    for (unsigned round = 0; round < RANDOM_ROUNDS; ++round) {
        for (unsigned lane = 0; lane < 16U; ++lane) {
            len[lane] = (size_t)(prng32() % (MAX_LEN + 1U));
            fill_random(buf[lane], len[lane]);
        }
        if (sm3_hash16_avx512(msg, len, got) != 0) return -1;
        for (unsigned lane = 0; lane < 16U; ++lane) {
            sm3_digest(msg[lane], len[lane], ref);
            if (memcmp(ref, got[lane], 32U) != 0) {
                fprintf(stderr, "AVX-512 random mismatch round=%u lane=%u len=%zu\n",
                        round, lane, len[lane]);
                return -1;
            }
        }
    }
    for (unsigned i = 0; i < 16U; ++i) free(buf[i]);
    return 0;
}

static int test_dispatch(void)
{
    enum { COUNT = 37 };
    uint8_t *buf[COUNT];
    const uint8_t *msg[COUNT];
    size_t len[COUNT];
    uint8_t got[COUNT][32];
    uint8_t ref[32];

    for (unsigned i = 0; i < COUNT; ++i) {
        len[i] = (size_t)((i * 197U + 55U) % 4097U);
        buf[i] = malloc(len[i] == 0U ? 1U : len[i]);
        if (buf[i] == NULL) return -1;
        fill_random(buf[i], len[i]);
        msg[i] = buf[i];
    }
    if (sm3_hash_batch_auto(msg, len, COUNT, got) != 0) return -1;
    for (unsigned i = 0; i < COUNT; ++i) {
        sm3_digest(msg[i], len[i], ref);
        if (memcmp(ref, got[i], 32U) != 0) {
            fprintf(stderr, "dispatch mismatch index=%u len=%zu\n", i, len[i]);
            return -1;
        }
        free(buf[i]);
    }
    return 0;
}

int main(void)
{
    printf("CPU AVX2:    %s\n", sm3_x86_has_avx2() ? "yes" : "no");
    printf("CPU AVX-512: %s\n", sm3_x86_has_avx512() ? "yes" : "no");
    printf("Auto backend: %s\n", sm3_x86_backend_name(sm3_x86_best_backend()));

    if (check_abc() != 0) return EXIT_FAILURE;

    if (sm3_x86_has_avx2()) {
        if (test_avx2_edges() != 0 || test_random_avx2() != 0) {
            return EXIT_FAILURE;
        }
        puts("[PASS] AVX2 edge and random differential tests");
    } else {
        puts("[SKIP] AVX2 tests: unsupported CPU/OS");
    }

    if (sm3_x86_has_avx512()) {
        if (test_avx512_edges() != 0 || test_random_avx512() != 0) {
            return EXIT_FAILURE;
        }
        puts("[PASS] AVX-512 edge and random differential tests");
    } else {
        puts("[SKIP] AVX-512 tests: unsupported CPU/OS");
    }

    if (test_dispatch() != 0) return EXIT_FAILURE;
    puts("[PASS] runtime dispatch test");
    puts("All SM3 x86 tests passed.");
    return EXIT_SUCCESS;
}
