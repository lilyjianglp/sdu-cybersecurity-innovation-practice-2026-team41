#ifndef SM3_X86_H
#define SM3_X86_H

#include <stddef.h>
#include <stdint.h>

#include "sm3.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum sm3_x86_backend {
    SM3_X86_BACKEND_SCALAR = 0,
    SM3_X86_BACKEND_AVX2 = 1,
    SM3_X86_BACKEND_AVX512 = 2
} sm3_x86_backend;

int sm3_x86_has_avx2(void);
int sm3_x86_has_avx512(void);
sm3_x86_backend sm3_x86_best_backend(void);
const char *sm3_x86_backend_name(sm3_x86_backend backend);

/* One-shot multi-buffer interfaces. Messages may have different lengths. */
int sm3_hash8_avx2(const uint8_t *messages[8],
                   const size_t lengths[8],
                   uint8_t digests[8][SM3_DIGEST_SIZE]);

int sm3_hash16_avx512(const uint8_t *messages[16],
                      const size_t lengths[16],
                      uint8_t digests[16][SM3_DIGEST_SIZE]);

/* Process any number of messages using AVX-512, AVX2, then scalar tails. */
int sm3_hash_batch_auto(const uint8_t *const *messages,
                        const size_t *lengths,
                        size_t count,
                        uint8_t (*digests)[SM3_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif
#endif
