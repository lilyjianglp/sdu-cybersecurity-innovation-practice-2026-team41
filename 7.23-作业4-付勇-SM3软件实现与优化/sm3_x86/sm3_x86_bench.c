#define _POSIX_C_SOURCE 200809L
#include "sm3_x86.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LANES 16U
#define RUNS 7U

static volatile uint8_t benchmark_sink;

static double now_seconds(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        exit(EXIT_FAILURE);
    }
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static int compare_double(const void *lhs, const void *rhs)
{
    const double a = *(const double *)lhs;
    const double b = *(const double *)rhs;
    return (a > b) - (a < b);
}

static double median(double values[RUNS])
{
    qsort(values, RUNS, sizeof(values[0]), compare_double);
    return values[RUNS / 2U];
}

static void fill_inputs(uint8_t *buffers[LANES], size_t length)
{
    for (unsigned lane = 0; lane < LANES; ++lane) {
        for (size_t i = 0; i < length; ++i) {
            buffers[lane][i] = (uint8_t)(i * 131U + lane * 17U + 0x5aU);
        }
    }
}

static double run_scalar(const uint8_t *messages[LANES],
                         const size_t lengths[LANES],
                         size_t iterations)
{
    uint8_t out[LANES][32];
    const double start = now_seconds();
    for (size_t it = 0; it < iterations; ++it) {
        for (unsigned lane = 0; lane < LANES; ++lane) {
            sm3_digest(messages[lane], lengths[lane], out[lane]);
        }
        benchmark_sink ^= out[it % LANES][it % 32U];
    }
    return now_seconds() - start;
}

static double run_avx2(const uint8_t *messages[LANES],
                       const size_t lengths[LANES],
                       size_t iterations)
{
    uint8_t out0[8][32];
    uint8_t out1[8][32];
    const uint8_t *group0[8];
    const uint8_t *group1[8];
    size_t len0[8];
    size_t len1[8];

    for (unsigned lane = 0; lane < 8U; ++lane) {
        group0[lane] = messages[lane];
        group1[lane] = messages[8U + lane];
        len0[lane] = lengths[lane];
        len1[lane] = lengths[8U + lane];
    }

    const double start = now_seconds();
    for (size_t it = 0; it < iterations; ++it) {
        (void)sm3_hash8_avx2(group0, len0, out0);
        (void)sm3_hash8_avx2(group1, len1, out1);
        benchmark_sink ^= out0[it % 8U][it % 32U] ^ out1[it % 8U][(it + 7U) % 32U];
    }
    return now_seconds() - start;
}

static double run_avx512(const uint8_t *messages[LANES],
                         const size_t lengths[LANES],
                         size_t iterations)
{
    uint8_t out[LANES][32];
    const double start = now_seconds();
    for (size_t it = 0; it < iterations; ++it) {
        (void)sm3_hash16_avx512(messages, lengths, out);
        benchmark_sink ^= out[it % LANES][it % 32U];
    }
    return now_seconds() - start;
}

static void print_result(const char *name,
                         size_t bytes_per_iteration,
                         size_t iterations,
                         double seconds,
                         double scalar_seconds)
{
    const double total_bytes = (double)bytes_per_iteration * (double)iterations;
    const double mib_per_second = total_bytes / seconds / (1024.0 * 1024.0);
    const double ns_per_byte = seconds * 1e9 / total_bytes;
    const double speedup = scalar_seconds > 0.0 ? scalar_seconds / seconds : 1.0;
    printf("%-18s %12.2f MiB/s  %8.3f ns/B  speedup %6.2fx\n",
           name, mib_per_second, ns_per_byte, speedup);
}

static int benchmark_length(size_t length, size_t total_mib)
{
    uint8_t *buffers[LANES] = {0};
    const uint8_t *messages[LANES];
    size_t lengths[LANES];
    double scalar_runs[RUNS];
    double avx2_runs[RUNS];
    double avx512_runs[RUNS];
    const size_t bytes_per_iteration = LANES * length;
    const size_t target_bytes = total_mib * 1024U * 1024U;
    const size_t iterations = bytes_per_iteration == 0U
                            ? 1U
                            : (target_bytes / bytes_per_iteration > 0U
                               ? target_bytes / bytes_per_iteration : 1U);

    for (unsigned lane = 0; lane < LANES; ++lane) {
        buffers[lane] = malloc(length == 0U ? 1U : length);
        if (buffers[lane] == NULL) {
            perror("malloc");
            return -1;
        }
        messages[lane] = buffers[lane];
        lengths[lane] = length;
    }
    fill_inputs(buffers, length);

    /* Warm-up all supported paths. */
    (void)run_scalar(messages, lengths, 2U);
    if (sm3_x86_has_avx2()) (void)run_avx2(messages, lengths, 2U);
    if (sm3_x86_has_avx512()) (void)run_avx512(messages, lengths, 2U);

    for (unsigned r = 0; r < RUNS; ++r) {
        scalar_runs[r] = run_scalar(messages, lengths, iterations);
        avx2_runs[r] = sm3_x86_has_avx2()
                     ? run_avx2(messages, lengths, iterations) : 0.0;
        avx512_runs[r] = sm3_x86_has_avx512()
                       ? run_avx512(messages, lengths, iterations) : 0.0;
    }

    const double scalar_time = median(scalar_runs);
    printf("\nMessage size: %zu bytes, batch: 16, iterations: %zu\n",
           length, iterations);
    print_result("scalar x16", bytes_per_iteration, iterations,
                 scalar_time, scalar_time);
    if (sm3_x86_has_avx2()) {
        print_result("AVX2 8-way x2", bytes_per_iteration, iterations,
                     median(avx2_runs), scalar_time);
    } else {
        puts("AVX2: unsupported; skipped");
    }
    if (sm3_x86_has_avx512()) {
        print_result("AVX-512 16-way", bytes_per_iteration, iterations,
                     median(avx512_runs), scalar_time);
    } else {
        puts("AVX-512: unsupported; skipped");
    }

    for (unsigned lane = 0; lane < LANES; ++lane) free(buffers[lane]);
    return 0;
}

int main(int argc, char **argv)
{
    static const size_t default_lengths[] = {64U, 256U, 1024U, 4096U, 16384U, 1048576U};
    size_t total_mib = 256U;

    printf("Best runtime backend: %s\n",
           sm3_x86_backend_name(sm3_x86_best_backend()));
    puts("Use taskset and perf stat externally for stable cycles/byte data.");

    if (argc >= 2) {
        const size_t length = (size_t)strtoull(argv[1], NULL, 10);
        if (argc >= 3) total_mib = (size_t)strtoull(argv[2], NULL, 10);
        return benchmark_length(length, total_mib) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    for (size_t i = 0; i < sizeof(default_lengths) / sizeof(default_lengths[0]); ++i) {
        if (benchmark_length(default_lengths[i], total_mib) != 0) {
            return EXIT_FAILURE;
        }
    }
    printf("\nbenchmark sink: %u\n", (unsigned)benchmark_sink);
    return EXIT_SUCCESS;
}
