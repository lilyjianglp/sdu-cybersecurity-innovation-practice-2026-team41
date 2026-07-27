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

typedef int (*xts_encrypt_fn)(
    const aes128_xts_key_t *, const uint8_t *, const uint8_t *, uint8_t *, size_t
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
    xts_encrypt_fn encrypt,
    const aes128_xts_key_t *ctx,
    const uint8_t tweak[16],
    const uint8_t *input,
    uint8_t *output,
    size_t bytes,
    size_t iterations
) {
    uint32_t checksum = UINT32_C(2166136261);
    const uint64_t tsc0 = read_tsc_start();
    const uint64_t ns0 = now_ns();
    for (size_t i = 0; i < iterations; ++i) {
        if (encrypt(ctx, tweak, input, output, bytes) != AES128_XTS_OK) {
            fputs("XTS benchmark operation failed\n", stderr);
            exit(EXIT_FAILURE);
        }
        checksum ^= output[(i * 131U) % bytes];
        checksum *= UINT32_C(16777619);
    }
    const uint64_t ns1 = now_ns();
    const uint64_t tsc1 = read_tsc_end();
    const sample_t sample = {
        .seconds = (double)(ns1 - ns0) / 1e9,
        .cycles = tsc1 - tsc0,
        .checksum = checksum
    };
    return sample;
}

static result_t benchmark_one(
    xts_encrypt_fn encrypt,
    const aes128_xts_key_t *ctx,
    const uint8_t tweak[16],
    const uint8_t *input,
    uint8_t *output,
    size_t bytes,
    size_t iterations
) {
    if (encrypt(ctx, tweak, input, output, bytes) != AES128_XTS_OK) {
        fputs("XTS benchmark warm-up failed\n", stderr);
        exit(EXIT_FAILURE);
    }

    sample_t samples[7];
    uint32_t checksum = 0U;
    for (size_t i = 0; i < 7U; ++i) {
        samples[i] = run_sample(
            encrypt, ctx, tweak, input, output, bytes, iterations
        );
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
        16U, 64U, 128U, 256U, 1024U, 8192U, 65536U, 1048576U
    };
    static const uint8_t key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    static const uint8_t tweak[16] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x2a,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };

    try_pin_cpu0();

    aes128_xts_key_t ctx;
    if (aes128_xts_init(&ctx, key) != AES128_XTS_OK) {
        fputs("XTS key initialization failed\n", stderr);
        return EXIT_FAILURE;
    }

    printf("XTS AES-NI batch path: %s\n",
           aes128_xts_aesni_supported() ? "enabled" : "software fallback");
    puts("AES-128-XTS reference vs AES-NI scalar vs AES-NI batch-tweak");
    printf("%-9s %10s %10s %10s %9s %9s %9s %8s %8s\n",
           "Bytes", "Ref MiB", "NI-Sc MiB", "NI-Bat MiB",
           "Ref c/B", "NI-Sc c/B", "NI-Bat c/B", "NI-Sc x", "NI-Bat x");

    volatile uint32_t sink = 0U;
    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); ++s) {
        const size_t bytes = sizes[s];
        const size_t target_bytes = 2U * 1024U * 1024U;
        size_t iterations = target_bytes / bytes;
        if (iterations < 8U) {
            iterations = 8U;
        }

        const size_t allocation_size = (bytes + 63U) & ~63U;
        uint8_t *input = aligned_alloc(64U, allocation_size);
        uint8_t *ref_output = aligned_alloc(64U, allocation_size);
        uint8_t *scalar_output = aligned_alloc(64U, allocation_size);
        uint8_t *batch_output = aligned_alloc(64U, allocation_size);
        if (input == NULL || ref_output == NULL || scalar_output == NULL ||
            batch_output == NULL) {
            fprintf(stderr, "allocation failed for %zu bytes\n", bytes);
            free(input); free(ref_output); free(scalar_output); free(batch_output);
            aes128_xts_clear(&ctx);
            return EXIT_FAILURE;
        }

        for (size_t i = 0; i < bytes; ++i) {
            input[i] = (uint8_t)(i * 29U + 7U);
        }

        const result_t ref = benchmark_one(
            aes128_xts_encrypt_ref, &ctx, tweak,
            input, ref_output, bytes, iterations
        );
        const result_t scalar = benchmark_one(
            aes128_xts_encrypt_aesni_scalar, &ctx, tweak,
            input, scalar_output, bytes, iterations
        );
        const result_t batch = benchmark_one(
            aes128_xts_encrypt_aesni_batch, &ctx, tweak,
            input, batch_output, bytes, iterations
        );

        if (memcmp(ref_output, scalar_output, bytes) != 0 ||
            memcmp(ref_output, batch_output, bytes) != 0) {
            fprintf(stderr, "XTS benchmark ciphertext mismatch at %zu bytes\n", bytes);
            free(input); free(ref_output); free(scalar_output); free(batch_output);
            aes128_xts_clear(&ctx);
            return EXIT_FAILURE;
        }

        sink = sink * UINT32_C(33) + ref.checksum;
        sink = sink * UINT32_C(33) + scalar.checksum;
        sink = sink * UINT32_C(33) + batch.checksum;

        printf("%-9zu %10.1f %10.1f %10.1f %9.3f %9.3f %9.3f %7.2fx %7.2fx\n",
               bytes,
               ref.mib_per_second, scalar.mib_per_second, batch.mib_per_second,
               ref.cycles_per_byte, scalar.cycles_per_byte, batch.cycles_per_byte,
               scalar.mib_per_second / ref.mib_per_second,
               batch.mib_per_second / ref.mib_per_second);

        free(input); free(ref_output); free(scalar_output); free(batch_output);
    }

    aes128_xts_clear(&ctx);
    fprintf(stderr, "benchmark checksum: %u\n", (unsigned)sink);
    return EXIT_SUCCESS;
}
