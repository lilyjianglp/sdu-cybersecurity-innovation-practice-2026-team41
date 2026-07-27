#define _GNU_SOURCE
#include "aes128.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(__linux__)
#include <sched.h>
#endif

#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
#endif

typedef int (*gcm_encrypt_fn)(
    const aes128_key_t *, const uint8_t *, size_t,
    const uint8_t *, size_t, const uint8_t *, uint8_t *, size_t,
    uint8_t *, size_t
);

typedef struct {
    double seconds;
    uint64_t cycles;
    uint32_t checksum;
} sample_t;

typedef struct {
    double mib_per_second;
    double cycles_per_byte;
    uint32_t checksum;
} result_t;

static uint64_t now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) != 0) {
        perror("clock_gettime");
        exit(EXIT_FAILURE);
    }
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static uint64_t read_tsc_start(void) {
#if defined(__x86_64__) || defined(__i386__)
    _mm_lfence();
    return __rdtsc();
#else
    return 0;
#endif
}

static uint64_t read_tsc_end(void) {
#if defined(__x86_64__) || defined(__i386__)
    unsigned aux;
    const uint64_t value = __rdtscp(&aux);
    _mm_lfence();
    return value;
#else
    return 0;
#endif
}

static void try_pin_cpu0(void) {
#if defined(__linux__)
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        fprintf(stderr, "Note: CPU affinity not set: %s\n", strerror(errno));
    }
#endif
}

static int compare_sample(const void *lhs, const void *rhs) {
    const sample_t *a = lhs;
    const sample_t *b = rhs;
    return (a->seconds > b->seconds) - (a->seconds < b->seconds);
}

static sample_t run_sample(
    gcm_encrypt_fn encrypt,
    const aes128_key_t *ctx,
    const uint8_t iv[12],
    const uint8_t aad[32],
    const uint8_t *input,
    uint8_t *output,
    size_t bytes,
    size_t iterations
) {
    uint32_t checksum = UINT32_C(2166136261);
    uint8_t tag[16];

    const uint64_t tsc0 = read_tsc_start();
    const uint64_t ns0 = now_ns();
    for (size_t i = 0; i < iterations; ++i) {
        if (encrypt(ctx, iv, 12U, aad, 32U, input, output, bytes, tag, sizeof(tag)) != AES128_GCM_OK) {
            fputs("GCM benchmark operation failed\n", stderr);
            exit(EXIT_FAILURE);
        }
        checksum ^= output[(i * 131U) % bytes];
        checksum *= UINT32_C(16777619);
        checksum ^= tag[i & 15U];
    }
    const uint64_t ns1 = now_ns();
    const uint64_t tsc1 = read_tsc_end();

    const sample_t result = {
        .seconds = (double)(ns1 - ns0) / 1e9,
        .cycles = tsc1 - tsc0,
        .checksum = checksum
    };
    return result;
}

static result_t benchmark_one(
    gcm_encrypt_fn encrypt,
    const aes128_key_t *ctx,
    const uint8_t iv[12],
    const uint8_t aad[32],
    const uint8_t *input,
    uint8_t *output,
    size_t bytes,
    size_t iterations
) {
    uint8_t tag[16];
    if (encrypt(ctx, iv, 12U, aad, 32U, input, output, bytes, tag, sizeof(tag)) != AES128_GCM_OK) {
        fputs("GCM benchmark warm-up failed\n", stderr);
        exit(EXIT_FAILURE);
    }

    sample_t samples[7];
    uint32_t checksum = 0;
    for (size_t i = 0; i < 7U; ++i) {
        samples[i] = run_sample(encrypt, ctx, iv, aad, input, output, bytes, iterations);
        checksum ^= samples[i].checksum + (uint32_t)i;
    }
    qsort(samples, 7U, sizeof(samples[0]), compare_sample);
    const sample_t median = samples[3];
    const double total_bytes = (double)bytes * (double)iterations;

    const result_t result = {
        .mib_per_second = total_bytes / median.seconds / (1024.0 * 1024.0),
        .cycles_per_byte = (double)median.cycles / total_bytes,
        .checksum = checksum
    };
    return result;
}

int main(void) {
    static const size_t sizes[] = {
        16, 64, 128, 256, 1024, 8192, 65536, 1048576
    };
    static const uint8_t key[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const uint8_t iv[12] = {
        0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe,0x01,0x23,0x45,0x67
    };
    static const uint8_t aad[32] = {
        0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,
        0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf,
        0xb0,0xb1,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,
        0xb8,0xb9,0xba,0xbb,0xbc,0xbd,0xbe,0xbf
    };

    try_pin_cpu0();

    aes128_key_t ctx;
    if (aes128_init(&ctx, key) != 0) {
        fputs("AES key initialization failed\n", stderr);
        return EXIT_FAILURE;
    }

    printf("AES-NI hardware path: %s\n", aes128_aesni_supported() ? "enabled" : "software fallback");
    printf("GCM PCLMULQDQ path: %s\n", aes128_gcm_pclmul_supported() ? "enabled" : "software fallback");
    puts("AES-128-GCM reference vs AES-NI/portable-GHASH vs AES-NI/PCLMUL");
    printf("%-9s %10s %10s %10s %9s %9s %9s %8s %8s\n",
           "Bytes", "Ref MiB", "NI-GH MiB", "PCL MiB",
           "Ref c/B", "NI-GH c/B", "PCL c/B", "NI-GH x", "PCL x");

    volatile uint32_t sink = 0;

    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); ++s) {
        const size_t bytes = sizes[s];
        const size_t target_bytes = 2U * 1024U * 1024U;
        size_t iterations = target_bytes / bytes;
        if (iterations < 8U) {
            iterations = 8U;
        }

        const size_t allocation_size = (bytes + 63U) & ~63U;
        uint8_t *input = aligned_alloc(64, allocation_size);
        uint8_t *ref_output = aligned_alloc(64, allocation_size);
        uint8_t *aesni_output = aligned_alloc(64, allocation_size);
        uint8_t *pclmul_output = aligned_alloc(64, allocation_size);
        if (input == NULL || ref_output == NULL || aesni_output == NULL || pclmul_output == NULL) {
            fprintf(stderr, "allocation failed for %zu bytes\n", bytes);
            free(input); free(ref_output); free(aesni_output); free(pclmul_output);
            aes128_clear(&ctx);
            return EXIT_FAILURE;
        }

        for (size_t i = 0; i < bytes; ++i) {
            input[i] = (uint8_t)(i * 29U + 7U);
        }

        const result_t ref = benchmark_one(
            aes128_gcm_encrypt_ref, &ctx, iv, aad, input, ref_output, bytes, iterations
        );
        const result_t aesni = benchmark_one(
            aes128_gcm_encrypt_aesni, &ctx, iv, aad, input, aesni_output, bytes, iterations
        );
        const result_t pclmul = benchmark_one(
            aes128_gcm_encrypt_pclmul, &ctx, iv, aad, input, pclmul_output, bytes, iterations
        );

        sink = sink * UINT32_C(33) + ref.checksum;
        sink = sink * UINT32_C(33) + aesni.checksum;
        sink = sink * UINT32_C(33) + pclmul.checksum;

        if (memcmp(ref_output, aesni_output, bytes) != 0 ||
            memcmp(ref_output, pclmul_output, bytes) != 0) {
            fprintf(stderr, "GCM benchmark ciphertext mismatch at %zu bytes\n", bytes);
            free(input); free(ref_output); free(aesni_output); free(pclmul_output);
            aes128_clear(&ctx);
            return EXIT_FAILURE;
        }

        printf("%-9zu %10.1f %10.1f %10.1f %9.3f %9.3f %9.3f %7.2fx %7.2fx\n",
               bytes,
               ref.mib_per_second, aesni.mib_per_second, pclmul.mib_per_second,
               ref.cycles_per_byte, aesni.cycles_per_byte, pclmul.cycles_per_byte,
               aesni.mib_per_second / ref.mib_per_second,
               pclmul.mib_per_second / ref.mib_per_second);

        free(input); free(ref_output); free(aesni_output); free(pclmul_output);
    }

    aes128_clear(&ctx);
    fprintf(stderr, "benchmark checksum: %u\n", (unsigned)sink);
    return EXIT_SUCCESS;
}
