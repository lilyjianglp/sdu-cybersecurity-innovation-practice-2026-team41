#ifndef SM3_H
#define SM3_H


#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


#define SM3_BLOCK_SIZE 64U


#define SM3_DIGEST_SIZE 32U


#define SM3_STATE_WORDS 8U


typedef struct sm3_ctx {
    uint32_t state[SM3_STATE_WORDS];
    uint64_t total_bytes;
    uint8_t buffer[SM3_BLOCK_SIZE];
    size_t buffer_len;
} sm3_ctx;


void sm3_init(sm3_ctx *ctx);


void sm3_update(sm3_ctx *ctx,
                const uint8_t *data,
                size_t len);


void sm3_final(sm3_ctx *ctx,
               uint8_t digest[SM3_DIGEST_SIZE]);


void sm3_digest(const uint8_t *data,
                size_t len,
                uint8_t digest[SM3_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif

#endif
