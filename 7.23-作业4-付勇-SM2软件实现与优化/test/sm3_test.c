

#include "sm3.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static unsigned int g_tests_run = 0U;
static unsigned int g_tests_failed = 0U;


static int hex_value(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }

    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }

    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }

    return -1;
}


static int hex_to_digest(
    const char *hex,
    uint8_t digest[SM3_DIGEST_SIZE])
{
    size_t i;

    if (hex == NULL || digest == NULL) {
        return 0;
    }

    if (strlen(hex) != SM3_DIGEST_SIZE * 2U) {
        return 0;
    }

    for (i = 0U; i < SM3_DIGEST_SIZE; ++i) {
        const int high = hex_value(hex[2U * i]);
        const int low = hex_value(hex[2U * i + 1U]);

        if (high < 0 || low < 0) {
            return 0;
        }

        digest[i] = (uint8_t)((high << 4) | low);
    }

    return 1;
}

static void print_digest(
    const uint8_t digest[SM3_DIGEST_SIZE])
{
    size_t i;

    for (i = 0U; i < SM3_DIGEST_SIZE; ++i) {
        printf("%02x", digest[i]);
    }
}


static void report_success(const char *name)
{
    printf("[PASS] %s\n", name);
}


static void report_digest_failure(
    const char *name,
    const uint8_t expected[SM3_DIGEST_SIZE],
    const uint8_t actual[SM3_DIGEST_SIZE])
{
    printf("[FAIL] %s\n", name);

    printf("       expected: ");
    print_digest(expected);
    putchar('\n');

    printf("       actual:   ");
    print_digest(actual);
    putchar('\n');
}


static int test_known_vector(
    const char *name,
    const uint8_t *message,
    size_t message_len,
    const char *expected_hex)
{
    uint8_t actual[SM3_DIGEST_SIZE];
    uint8_t expected[SM3_DIGEST_SIZE];

    ++g_tests_run;

    if (!hex_to_digest(expected_hex, expected)) {
        printf("[FAIL] %s\n", name);
        printf("       invalid expected digest string\n");

        ++g_tests_failed;
        return 0;
    }

    sm3_digest(message, message_len, actual);

    if (memcmp(actual, expected, SM3_DIGEST_SIZE) != 0) {
        report_digest_failure(name, expected, actual);

        ++g_tests_failed;
        return 0;
    }

    report_success(name);
    return 1;
}


static void sm3_digest_in_chunks(
    const uint8_t *message,
    size_t message_len,
    const size_t *chunk_pattern,
    size_t pattern_len,
    uint8_t digest[SM3_DIGEST_SIZE])
{
    sm3_ctx ctx;
    size_t offset = 0U;
    size_t pattern_index = 0U;

    sm3_init(&ctx);

   
    sm3_update(&ctx, NULL, 0U);

    while (offset < message_len) {
        size_t chunk_len = chunk_pattern[pattern_index];

       
        if (chunk_len == 0U) {
            chunk_len = 1U;
        }

        if (chunk_len > message_len - offset) {
            chunk_len = message_len - offset;
        }

        sm3_update(&ctx, message + offset, chunk_len);

        offset += chunk_len;
        pattern_index = (pattern_index + 1U) % pattern_len;
    }

    sm3_final(&ctx, digest);
}


static int test_streaming_pattern(
    const char *name,
    const uint8_t *message,
    size_t message_len,
    const size_t *chunk_pattern,
    size_t pattern_len)
{
    uint8_t one_shot[SM3_DIGEST_SIZE];
    uint8_t streamed[SM3_DIGEST_SIZE];

    ++g_tests_run;

    sm3_digest(message, message_len, one_shot);

    sm3_digest_in_chunks(
        message,
        message_len,
        chunk_pattern,
        pattern_len,
        streamed);

    if (memcmp(one_shot, streamed, SM3_DIGEST_SIZE) != 0) {
        report_digest_failure(name, one_shot, streamed);

        ++g_tests_failed;
        return 0;
    }

    report_success(name);
    return 1;
}


static int test_million_a(void)
{
    static const char expected_hex[] =
        "c8aaf89429554029e231941a2acc0ad6"
        "1ff2a5acd8fadd25847a3a732b3b02c3";

    uint8_t expected[SM3_DIGEST_SIZE];
    uint8_t actual[SM3_DIGEST_SIZE];
    uint8_t block[1000];

    sm3_ctx ctx;
    size_t i;

    ++g_tests_run;

    if (!hex_to_digest(expected_hex, expected)) {
        printf("[FAIL] one million 'a' characters\n");
        printf("       invalid expected digest string\n");

        ++g_tests_failed;
        return 0;
    }

    memset(block, 'a', sizeof(block));

    sm3_init(&ctx);

    
    for (i = 0U; i < 1000U; ++i) {
        sm3_update(&ctx, block, sizeof(block));
    }

    sm3_final(&ctx, actual);

    if (memcmp(actual, expected, SM3_DIGEST_SIZE) != 0) {
        report_digest_failure(
            "one million 'a' characters",
            expected,
            actual);

        ++g_tests_failed;
        return 0;
    }

    report_success("one million 'a' characters");
    return 1;
}


static void test_padding_boundaries(void)
{
    struct boundary_vector {
        size_t length;
        const char *expected_hex;
    };

    static const struct boundary_vector vectors[] = {
        {
            0U,
            "1ab21d8355cfa17f8e61194831e81a8f"
            "22bec8c728fefb747ed035eb5082aa2b"
        },
        {
            1U,
            "2daef60e7a0b8f5e024c81cd2ab3109f"
            "2b4f155cf83adeb2ae5532f74a157fdf"
        },
        {
            55U,
            "a79cf9dcee3404abf7f769698201647fd"
            "9d3ff61d629d0f58bb4b5579a427db8"
        },
        {
            56U,
            "62f7363b15f4de76dd925c493b9d6d00"
            "d4ba0ef2a1f334c1d0f13b293aeb40d1"
        },
        {
            57U,
            "441f67cc31781dd2986fc612b92dfade"
            "871d81357f2487f5c86d94a8c6778d82"
        },
        {
            63U,
            "6165e4cbb15cde01c6226e0015a47f71"
            "0f8f8e1f2c296700033bb34d9212109c"
        },
        {
            64U,
            "93566f236d157aae078d1ddb5cebdbba"
            "1520b5142e22a8915564345ba2ae1d63"
        },
        {
            65U,
            "c886e6814be748285a10b28ae62ddacd"
            "85db830cd2cf3a2bfa2f729c15f63618"
        },
        {
            119U,
            "8f3ea392a89a7119982d6634660db1a9"
            "5f35d68267a2235e3255998a857f4fbf"
        },
        {
            120U,
            "6babee35e6a1515af9d6255109c24f3c"
            "08897829422c6225d235fd4c8527e9ec"
        },
        {
            121U,
            "501bf851d9377e2f02e6dc2da58795b5"
            "a7337d94efbea64bcbaf0b3df11e240c"
        },
        {
            127U,
            "bca3436d828517a6a6893a9e309e06e7"
            "b7b29c6e3f78b4814b23efe149962980"
        },
        {
            128U,
            "a9e7985473ca09df1510d83b572f7237"
            "5430756c4a661b00724afeb8b75dd0a5"
        },
        {
            129U,
            "2783a0e9b3767a694f90027806e392ae"
            "959d919baed7ceca40c7c8077711cb7b"
        },
        {
            1024U,
            "1f00bad6a72e851e0f6e94fd317f97b7"
            "4d5fbc4c090aefb91e7554e3f9c8c7fb"
        }
    };

    uint8_t message[1024];
    size_t i;

    for (i = 0U; i < sizeof(message); ++i) {
        message[i] = (uint8_t)i;
    }

    printf("\nPadding and block boundary tests:\n");

    for (i = 0U; i < sizeof(vectors) / sizeof(vectors[0]); ++i) {
        char name[80];

        const int written = snprintf(
            name,
            sizeof(name),
            "sequential-byte message, length %zu",
            vectors[i].length);

        if (written < 0 || (size_t)written >= sizeof(name)) {
            printf("[FAIL] unable to construct boundary test name\n");

            ++g_tests_run;
            ++g_tests_failed;
            continue;
        }

        test_known_vector(
            name,
            message,
            vectors[i].length,
            vectors[i].expected_hex);
    }
}


static void test_streaming_updates(void)
{
    static const size_t one_byte_pattern[] = {
        1U
    };

    static const size_t small_prime_pattern[] = {
        2U, 3U, 5U, 7U, 11U
    };

    static const size_t block_boundary_pattern[] = {
        63U, 1U, 64U, 65U, 17U
    };

    static const size_t irregular_pattern[] = {
        127U, 13U, 256U, 9U, 1000U, 31U
    };

    const size_t message_len = 4097U;
    uint8_t *message;
    size_t i;

    message = (uint8_t *)malloc(message_len);

    if (message == NULL) {
        printf("[FAIL] streaming test allocation\n");

        ++g_tests_run;
        ++g_tests_failed;
        return;
    }

   
    for (i = 0U; i < message_len; ++i) {
        message[i] = (uint8_t)(
            ((uint32_t)i * UINT32_C(37)
             + UINT32_C(11))
            & UINT32_C(0xFF));
    }

    printf("\nStreaming update tests:\n");

    test_streaming_pattern(
        "streaming, one byte per update",
        message,
        message_len,
        one_byte_pattern,
        sizeof(one_byte_pattern) / sizeof(one_byte_pattern[0]));

    test_streaming_pattern(
        "streaming, small prime-size chunks",
        message,
        message_len,
        small_prime_pattern,
        sizeof(small_prime_pattern)
            / sizeof(small_prime_pattern[0]));

    test_streaming_pattern(
        "streaming, chunks around 64-byte boundary",
        message,
        message_len,
        block_boundary_pattern,
        sizeof(block_boundary_pattern)
            / sizeof(block_boundary_pattern[0]));

    test_streaming_pattern(
        "streaming, irregular large and small chunks",
        message,
        message_len,
        irregular_pattern,
        sizeof(irregular_pattern)
            / sizeof(irregular_pattern[0]));

    free(message);
}


static int test_abc_streaming_known_vector(void)
{
    static const uint8_t message[] = {
        (uint8_t)'a',
        (uint8_t)'b',
        (uint8_t)'c'
    };

    static const char expected_hex[] =
        "66c7f0f462eeedd9d1f2d46bdc10e4e"
        "24167c4875cf2f7a2297da02b8f4ba8e0";

    uint8_t expected[SM3_DIGEST_SIZE];
    uint8_t actual[SM3_DIGEST_SIZE];

    sm3_ctx ctx;

    ++g_tests_run;

    if (!hex_to_digest(expected_hex, expected)) {
        printf("[FAIL] streaming \"abc\" known vector\n");
        printf("       invalid expected digest string\n");

        ++g_tests_failed;
        return 0;
    }

    sm3_init(&ctx);

    sm3_update(&ctx, message, 1U);
    sm3_update(&ctx, message + 1U, 1U);
    sm3_update(&ctx, message + 2U, 1U);

    sm3_final(&ctx, actual);

    if (memcmp(actual, expected, SM3_DIGEST_SIZE) != 0) {
        report_digest_failure(
            "streaming \"abc\" known vector",
            expected,
            actual);

        ++g_tests_failed;
        return 0;
    }

    report_success("streaming \"abc\" known vector");
    return 1;
}


int main(void)
{
    static const uint8_t abc_message[] = {
        (uint8_t)'a',
        (uint8_t)'b',
        (uint8_t)'c'
    };

    static const uint8_t abcd_repeated_message[] =
        "abcdabcdabcdabcd"
        "abcdabcdabcdabcd"
        "abcdabcdabcdabcd"
        "abcdabcdabcdabcd";

    printf("============================================================\n");
    printf("SM3 portable reference implementation tests\n");
    printf("============================================================\n\n");

    printf("Known SM3 test vectors:\n");

   
    test_known_vector(
        "empty message",
        NULL,
        0U,
        "1ab21d8355cfa17f8e61194831e81a8f"
        "22bec8c728fefb747ed035eb5082aa2b");

    test_known_vector(
        "\"abc\"",
        abc_message,
        sizeof(abc_message),
        "66c7f0f462eeedd9d1f2d46bdc10e4e"
        "24167c4875cf2f7a2297da02b8f4ba8e0");

    
    test_known_vector(
        "\"abcd\" repeated 16 times",
        abcd_repeated_message,
        sizeof(abcd_repeated_message) - 1U,
        "debe9ff92275b8a138604889c18e5a4d"
        "6fdb70e5387e5765293dcba39c0c5732");

    test_abc_streaming_known_vector();
    test_million_a();

    test_padding_boundaries();
    test_streaming_updates();

    printf("\n============================================================\n");
    printf("Tests run:    %u\n", g_tests_run);
    printf("Tests passed: %u\n", g_tests_run - g_tests_failed);
    printf("Tests failed: %u\n", g_tests_failed);
    printf("============================================================\n");

    if (g_tests_failed != 0U) {
        return EXIT_FAILURE;
    }

    printf("All SM3 tests passed.\n");
    return EXIT_SUCCESS;
}
