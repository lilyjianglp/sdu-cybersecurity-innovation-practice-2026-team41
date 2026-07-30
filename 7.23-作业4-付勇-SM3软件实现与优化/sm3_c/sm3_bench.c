#define _POSIX_C_SOURCE 200809L

#include "sm3.h"

#include <errno.h>
#include <float.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static volatile uint32_t bench_sink;

static double get_time(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        exit(EXIT_FAILURE);
    }

    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static void fill_input(uint8_t *data, size_t len)
{
    size_t i;

    for (i = 0; i < len; ++i) {
        data[i] = (uint8_t)(i * 131U + 17U);
    }
}

static void run_benchmark(size_t message_size, size_t target_bytes)
{
    uint8_t *message;
    uint8_t digest[SM3_DIGEST_SIZE];
    size_t iterations;
    size_t processed_bytes;
    double best_time = DBL_MAX;
    unsigned int trial;

    message = malloc(message_size);

    if (message == NULL) {
        fprintf(stderr, "Unable to allocate %zu bytes\n", message_size);
        exit(EXIT_FAILURE);
    }

    fill_input(message, message_size);

    iterations =
        (target_bytes + message_size - 1U) / message_size;

    if (iterations == 0U) {
        iterations = 1U;
    }

    processed_bytes = iterations * message_size;

    for (trial = 0U; trial < 8U; ++trial) {
        sm3_digest(message, message_size, digest);
    }

    for (trial = 0U; trial < 3U; ++trial) {
        uint32_t checksum = 0U;
        size_t i;
        double start;
        double elapsed;

        start = get_time();

        for (i = 0U; i < iterations; ++i) {
            sm3_digest(message, message_size, digest);

            checksum ^=
                (uint32_t)digest[0]
                | ((uint32_t)digest[7] << 8U)
                | ((uint32_t)digest[15] << 16U)
                | ((uint32_t)digest[31] << 24U);
        }

        elapsed = get_time() - start;

        bench_sink ^= checksum;

        if (elapsed < best_time) {
            best_time = elapsed;
        }
    }

    printf(
        "%12zu  %12zu  %12.2f  %10.3f\n",
        message_size,
        iterations,
        ((double)processed_bytes / 1000000.0) / best_time,
        best_time * 1e9 / (double)processed_bytes);

    free(message);
}

static int parse_size(const char *text, size_t *value)
{
    char *end;
    unsigned long long result;

    errno = 0;
    result = strtoull(text, &end, 10);

    if (errno != 0 || *text == '\0' || *end != '\0') {
        return 0;
    }

    *value = (size_t)result;
    return 1;
}

int main(int argc, char **argv)
{
#if defined(SM3_USE_ARM64_ASM)
    const char *implementation = "arm64_asm";
#elif defined(SM3_USE_ARM64_NEON)
    const char *implementation = "arm64_neon";
#else
    const char *implementation = "ref";
#endif

    printf("SM3 implementation: %s\n", implementation);
    printf("%12s  %12s  %12s  %10s\n",
           "message(B)",
           "iterations",
           "MB/s",
           "ns/byte");

    if (argc == 3) {
        size_t message_size;
        size_t total_mb;

        if (!parse_size(argv[1], &message_size)
            || !parse_size(argv[2], &total_mb)
            || message_size == 0U
            || total_mb == 0U) {
            fprintf(stderr,
                    "Usage: %s [message_size total_MB]\n",
                    argv[0]);
            return EXIT_FAILURE;
        }

        run_benchmark(
            message_size,
            total_mb * 1000000U);

        return EXIT_SUCCESS;
    }

    {
        static const size_t sizes[] = {
            64U,
            1024U,
            16384U,
            1024U * 1024U
        };

        const size_t target_bytes =
            64U * 1000000U;

        size_t i;

        for (i = 0U;
             i < sizeof(sizes) / sizeof(sizes[0]);
             ++i) {
            run_benchmark(sizes[i], target_bytes);
        }
    }

    return EXIT_SUCCESS;
}
