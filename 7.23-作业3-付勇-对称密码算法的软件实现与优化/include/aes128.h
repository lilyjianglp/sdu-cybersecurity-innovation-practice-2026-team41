#ifndef AES128_H
#define AES128_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AES128_BLOCK_SIZE 16u
#define AES128_KEY_SIZE 16u
#define AES128_ROUNDS 10u
#define AES128_EXPANDED_KEY_SIZE 176u

#define AES128_CTR_OK 0
#define AES128_CTR_INVALID_ARGUMENT (-1)
#define AES128_CTR_COUNTER_EXHAUSTED (-2)

#define AES128_GCM_OK 0
#define AES128_GCM_INVALID_ARGUMENT (-1)
#define AES128_GCM_TAG_MISMATCH (-2)
#define AES128_GCM_LENGTH_LIMIT (-3)

#define AES128_XTS_KEY_SIZE 32u
#define AES128_XTS_MAX_BLOCKS ((size_t)1u << 20)

#define AES128_XTS_OK 0
#define AES128_XTS_INVALID_ARGUMENT (-1)
#define AES128_XTS_DATA_UNIT_TOO_SHORT (-2)
#define AES128_XTS_WEAK_KEY (-3)
#define AES128_XTS_LENGTH_LIMIT (-4)

typedef struct {
    uint8_t round_keys[AES128_EXPANDED_KEY_SIZE];
} aes128_key_t;

typedef struct {
    aes128_key_t data_key;
    aes128_key_t tweak_key;
} aes128_xts_key_t;

/* Expand a 128-bit key into 11 round keys. Returns 0 on success. */
int aes128_init(aes128_key_t *ctx, const uint8_t key[AES128_KEY_SIZE]);

/* Clear key material using volatile stores. */
void aes128_clear(aes128_key_t *ctx);

/* Straightforward byte-oriented reference implementation. */
void aes128_encrypt_block_ref(
    const aes128_key_t *ctx,
    const uint8_t in[AES128_BLOCK_SIZE],
    uint8_t out[AES128_BLOCK_SIZE]
);

void aes128_decrypt_block_ref(
    const aes128_key_t *ctx,
    const uint8_t in[AES128_BLOCK_SIZE],
    uint8_t out[AES128_BLOCK_SIZE]
);

/* ECB-like raw block helpers used internally by modes and benchmarks. */
void aes128_encrypt_blocks_ref(
    const aes128_key_t *ctx,
    const uint8_t *in,
    uint8_t *out,
    size_t blocks
);

void aes128_decrypt_blocks_ref(
    const aes128_key_t *ctx,
    const uint8_t *in,
    uint8_t *out,
    size_t blocks
);

/* Four-table encryption implementation. The tables merge SubBytes,
 * ShiftRows and MixColumns for rounds 1-9. This implementation is fast but
 * intentionally not constant-time because table indices depend on secret data. */
void aes128_encrypt_block_ttable(
    const aes128_key_t *ctx,
    const uint8_t in[AES128_BLOCK_SIZE],
    uint8_t out[AES128_BLOCK_SIZE]
);

void aes128_encrypt_blocks_ttable(
    const aes128_key_t *ctx,
    const uint8_t *in,
    uint8_t *out,
    size_t blocks
);

/* Runtime availability check for the x86 AVX2 implementation. */
int aes128_avx2_supported(void);

/* Eight-way AVX2 implementation. Full groups of eight blocks use AVX2
 * gather and byte-shuffle instructions; remaining blocks fall back to the
 * scalar T-table implementation. The function is safe to call on machines
 * without AVX2 because it performs runtime dispatch. */
void aes128_encrypt_blocks_avx2(
    const aes128_key_t *ctx,
    const uint8_t *in,
    uint8_t *out,
    size_t blocks
);

/* Runtime availability check for the x86 AES-NI implementation. */
int aes128_aesni_supported(void);

/* AES-NI encryption/decryption. Full groups of eight and four blocks are
 * interleaved to hide AES round latency; remaining blocks use the same
 * hardware instructions one at a time. On unsupported machines, encryption
 * falls back to T-table and decryption falls back to the reference backend. */
void aes128_encrypt_block_aesni(
    const aes128_key_t *ctx,
    const uint8_t in[AES128_BLOCK_SIZE],
    uint8_t out[AES128_BLOCK_SIZE]
);

void aes128_decrypt_block_aesni(
    const aes128_key_t *ctx,
    const uint8_t in[AES128_BLOCK_SIZE],
    uint8_t out[AES128_BLOCK_SIZE]
);

void aes128_encrypt_blocks_aesni(
    const aes128_key_t *ctx,
    const uint8_t *in,
    uint8_t *out,
    size_t blocks
);

void aes128_decrypt_blocks_aesni(
    const aes128_key_t *ctx,
    const uint8_t *in,
    uint8_t *out,
    size_t blocks
);

/* AES-CTR mode. The 128-bit counter is interpreted in big-endian order and
 * updated by ceil(length / 16) on success. Encryption and decryption are the
 * same operation. Exact in-place operation (in == out) is supported; other
 * partially overlapping buffers are not supported. The functions reject a
 * request that would wrap the counter modulo 2^128. */
int aes128_ctr_aesni_supported(void);

int aes128_ctr_crypt_ref(
    const aes128_key_t *ctx,
    uint8_t counter[AES128_BLOCK_SIZE],
    const uint8_t *in,
    uint8_t *out,
    size_t length
);

int aes128_ctr_crypt_ttable(
    const aes128_key_t *ctx,
    uint8_t counter[AES128_BLOCK_SIZE],
    const uint8_t *in,
    uint8_t *out,
    size_t length
);

int aes128_ctr_crypt_avx2(
    const aes128_key_t *ctx,
    uint8_t counter[AES128_BLOCK_SIZE],
    const uint8_t *in,
    uint8_t *out,
    size_t length
);

int aes128_ctr_crypt_aesni(
    const aes128_key_t *ctx,
    uint8_t counter[AES128_BLOCK_SIZE],
    const uint8_t *in,
    uint8_t *out,
    size_t length
);

/* AES-GCM authenticated encryption. IVs of arbitrary byte length are accepted;
 * the 96-bit IV fast path specified by SP 800-38D is used when iv_length == 12.
 * AAD and plaintext/ciphertext may have arbitrary byte lengths. Standard tag lengths of 4, 8, and 12 through 16 bytes are supported. Exact in-place operation is supported.
 * Decryption authenticates before releasing plaintext, so output remains
 * unchanged on tag failure. Partially overlapping buffers are not supported. */
int aes128_gcm_pclmul_supported(void);

int aes128_gcm_encrypt_ref(
    const aes128_key_t *ctx,
    const uint8_t *iv, size_t iv_length,
    const uint8_t *aad, size_t aad_length,
    const uint8_t *plaintext, uint8_t *ciphertext, size_t length,
    uint8_t *tag, size_t tag_length
);

int aes128_gcm_decrypt_ref(
    const aes128_key_t *ctx,
    const uint8_t *iv, size_t iv_length,
    const uint8_t *aad, size_t aad_length,
    const uint8_t *ciphertext, uint8_t *plaintext, size_t length,
    const uint8_t *tag, size_t tag_length
);

/* AES-NI accelerates GCTR while GHASH remains the portable reference multiply. */
int aes128_gcm_encrypt_aesni(
    const aes128_key_t *ctx,
    const uint8_t *iv, size_t iv_length,
    const uint8_t *aad, size_t aad_length,
    const uint8_t *plaintext, uint8_t *ciphertext, size_t length,
    uint8_t *tag, size_t tag_length
);

int aes128_gcm_decrypt_aesni(
    const aes128_key_t *ctx,
    const uint8_t *iv, size_t iv_length,
    const uint8_t *aad, size_t aad_length,
    const uint8_t *ciphertext, uint8_t *plaintext, size_t length,
    const uint8_t *tag, size_t tag_length
);

/* AES-NI GCTR plus PCLMULQDQ-accelerated GHASH. On unsupported x86 systems,
 * this interface falls back to AES-NI/reference-GHASH safely. */
int aes128_gcm_encrypt_pclmul(
    const aes128_key_t *ctx,
    const uint8_t *iv, size_t iv_length,
    const uint8_t *aad, size_t aad_length,
    const uint8_t *plaintext, uint8_t *ciphertext, size_t length,
    uint8_t *tag, size_t tag_length
);

int aes128_gcm_decrypt_pclmul(
    const aes128_key_t *ctx,
    const uint8_t *iv, size_t iv_length,
    const uint8_t *aad, size_t aad_length,
    const uint8_t *ciphertext, uint8_t *plaintext, size_t length,
    const uint8_t *tag, size_t tag_length
);

/* AES-XTS for storage data units. The combined key contains two independent
 * AES-128 keys: the first protects data and the second encrypts the 16-byte
 * tweak. Data units must contain at least one complete AES block and at most
 * 2^20 blocks. Ciphertext stealing handles non-multiple-of-16 lengths. Exact
 * in-place operation is supported; partially overlapping buffers are not. */
int aes128_xts_init(
    aes128_xts_key_t *ctx,
    const uint8_t key[AES128_XTS_KEY_SIZE]
);
void aes128_xts_clear(aes128_xts_key_t *ctx);
int aes128_xts_aesni_supported(void);

int aes128_xts_encrypt_ref(
    const aes128_xts_key_t *ctx,
    const uint8_t tweak[AES128_BLOCK_SIZE],
    const uint8_t *plaintext, uint8_t *ciphertext, size_t length
);
int aes128_xts_decrypt_ref(
    const aes128_xts_key_t *ctx,
    const uint8_t tweak[AES128_BLOCK_SIZE],
    const uint8_t *ciphertext, uint8_t *plaintext, size_t length
);

/* AES-NI with scalar tweak progression and one-block XEX processing. */
int aes128_xts_encrypt_aesni_scalar(
    const aes128_xts_key_t *ctx,
    const uint8_t tweak[AES128_BLOCK_SIZE],
    const uint8_t *plaintext, uint8_t *ciphertext, size_t length
);
int aes128_xts_decrypt_aesni_scalar(
    const aes128_xts_key_t *ctx,
    const uint8_t tweak[AES128_BLOCK_SIZE],
    const uint8_t *ciphertext, uint8_t *plaintext, size_t length
);

/* AES-NI with batches of eight/four blocks. Sequential tweaks are generated
 * ahead of each batch and SIMD XOR performs XEX whitening. */
int aes128_xts_encrypt_aesni_batch(
    const aes128_xts_key_t *ctx,
    const uint8_t tweak[AES128_BLOCK_SIZE],
    const uint8_t *plaintext, uint8_t *ciphertext, size_t length
);
int aes128_xts_decrypt_aesni_batch(
    const aes128_xts_key_t *ctx,
    const uint8_t tweak[AES128_BLOCK_SIZE],
    const uint8_t *ciphertext, uint8_t *plaintext, size_t length
);

#ifdef __cplusplus
}
#endif

#endif
