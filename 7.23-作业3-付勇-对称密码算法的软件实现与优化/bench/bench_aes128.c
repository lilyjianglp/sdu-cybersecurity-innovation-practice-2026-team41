#define _GNU_SOURCE
#include "aes128.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(__linux__)
#include <sched.h>
#include <unistd.h>
#endif

#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
#endif

typedef struct {
    double seconds;
    uint64_t cycles;
    uint8_t checksum;
} sample_t;

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
    uint64_t value = __rdtscp(&aux);
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
    const aes128_key_t *ctx,
    const uint8_t *input,
    uint8_t *output,
    size_t bytes,
    size_t iterations
) {
    const size_t blocks = bytes / AES128_BLOCK_SIZE;
    uint8_t checksum = 0;

    const uint64_t tsc0 = read_tsc_start();
    const uint64_t ns0 = now_ns();
    for (size_t i = 0; i < iterations; ++i) {
        aes128_encrypt_blocks_ref(ctx, input, output, blocks);
        checksum ^= output[(i * 131U) % bytes];
    }
    const uint64_t ns1 = now_ns();
    const uint64_t tsc1 = read_tsc_end();

    sample_t result = {
        .seconds = (double)(ns1 - ns0) / 1e9,
        .cycles = tsc1 - tsc0,
        .checksum = checksum
    };
    return result;
}

int main(void) {
    static const size_t sizes[] = {
        16, 64, 256, 1024, 8192, 65536, 1048576
    };
    static const uint8_t key[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    try_pin_cpu0();

    aes128_key_t ctx;
    if (aes128_init(&ctx, key) != 0) {
        fprintf(stderr, "AES key initialization failed\n");
        return EXIT_FAILURE;
    }

    printf("AES-128 reference benchmark\n");
    printf("%-10s %12s %12s %12s\n", "Bytes", "MiB/s", "ns/byte", "cycles/B");

    volatile uint8_t sink = 0;

    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); ++s) {
        const size_t bytes = sizes[s];
        const size_t target_bytes = 16U * 1024U * 1024U;
        size_t iterations = target_bytes / bytes;
        if (iterations < 8) {
            iterations = 8;
        }

        uint8_t *input = aligned_alloc(64, (bytes + 63U) & ~63U);
        uint8_t *output = aligned_alloc(64, (bytes + 63U) & ~63U);
        if (input == NULL || output == NULL) {
            fprintf(stderr, "allocation failed for %zu bytes\n", bytes);
            free(input);
            free(output);
            aes128_clear(&ctx);
            return EXIT_FAILURE;
        }

        for (size_t i = 0; i < bytes; ++i) {
            input[i] = (uint8_t)(i * 29U + 7U);
        }
        memset(output, 0, bytes);

        aes128_encrypt_blocks_ref(&ctx, input, output, bytes / 16);

        sample_t samples[5];
        for (size_t i = 0; i < 5; ++i) {
            samples[i] = run_sample(&ctx, input, output, bytes, iterations);
            sink ^= samples[i].checksum;
        }
        qsort(samples, 5, sizeof(samples[0]), compare_sample);
        const sample_t median = samples[2];

        const double total_bytes = (double)bytes * (double)iterations;
        const double mib_per_second = total_bytes / median.seconds / (1024.0 * 1024.0);
        const double ns_per_byte = median.seconds * 1e9 / total_bytes;
        const double cycles_per_byte = (double)median.cycles / total_bytes;

        printf("%-10zu %12.2f %12.3f %12.3f\n",
               bytes, mib_per_second, ns_per_byte, cycles_per_byte);

        free(input);
        free(output);
    }

    aes128_clear(&ctx);
    fprintf(stderr, "benchmark checksum: %u\n", (unsigned)sink);
    return EXIT_SUCCESS;
}
