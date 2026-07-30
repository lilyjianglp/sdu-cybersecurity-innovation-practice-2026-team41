#include "sm3_x86.h"

int sm3_x86_has_avx2(void)
{
#if defined(__x86_64__) || defined(__i386__)
#  if defined(__GNUC__) || defined(__clang__)
    __builtin_cpu_init();
    return __builtin_cpu_supports("avx2") != 0;
#  else
    return 0;
#  endif
#else
    return 0;
#endif
}

int sm3_x86_has_avx512(void)
{
#if defined(__x86_64__) || defined(__i386__)
#  if defined(__GNUC__) || defined(__clang__)
    __builtin_cpu_init();
    return __builtin_cpu_supports("avx512f") != 0;
#  else
    return 0;
#  endif
#else
    return 0;
#endif
}

sm3_x86_backend sm3_x86_best_backend(void)
{
    if (sm3_x86_has_avx512()) {
        return SM3_X86_BACKEND_AVX512;
    }
    if (sm3_x86_has_avx2()) {
        return SM3_X86_BACKEND_AVX2;
    }
    return SM3_X86_BACKEND_SCALAR;
}

const char *sm3_x86_backend_name(sm3_x86_backend backend)
{
    switch (backend) {
    case SM3_X86_BACKEND_AVX512:
        return "AVX-512 (16-way)";
    case SM3_X86_BACKEND_AVX2:
        return "AVX2 (8-way)";
    default:
        return "scalar";
    }
}

int sm3_hash_batch_auto(const uint8_t *const *messages,
                        const size_t *lengths,
                        size_t count,
                        uint8_t (*digests)[SM3_DIGEST_SIZE])
{
    size_t offset = 0U;
    const int have_avx512 = sm3_x86_has_avx512();
    const int have_avx2 = sm3_x86_has_avx2();

    if (count == 0U) {
        return 0;
    }
    if (messages == NULL || lengths == NULL || digests == NULL) {
        return -1;
    }

    while (have_avx512 && count - offset >= 16U) {
        const uint8_t *group[16];
        size_t group_lengths[16];
        for (unsigned lane = 0; lane < 16U; ++lane) {
            group[lane] = messages[offset + lane];
            group_lengths[lane] = lengths[offset + lane];
        }
        if (sm3_hash16_avx512(group, group_lengths, digests + offset) != 0) {
            return -1;
        }
        offset += 16U;
    }

    while (have_avx2 && count - offset >= 8U) {
        const uint8_t *group[8];
        size_t group_lengths[8];
        for (unsigned lane = 0; lane < 8U; ++lane) {
            group[lane] = messages[offset + lane];
            group_lengths[lane] = lengths[offset + lane];
        }
        if (sm3_hash8_avx2(group, group_lengths, digests + offset) != 0) {
            return -1;
        }
        offset += 8U;
    }

    for (; offset < count; ++offset) {
        if (messages[offset] == NULL && lengths[offset] != 0U) {
            return -1;
        }
        sm3_digest(messages[offset], lengths[offset], digests[offset]);
    }
    return 0;
}
