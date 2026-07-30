#include "sm3_x86.h"

#include <stdio.h>
#include <stdlib.h>

static int read_file(const char *path, uint8_t **data, size_t *length)
{
    FILE *fp = fopen(path, "rb");
    long end;
    size_t n;

    if (fp == NULL) {
        perror(path);
        return -1;
    }
    if (fseek(fp, 0, SEEK_END) != 0 || (end = ftell(fp)) < 0 ||
        fseek(fp, 0, SEEK_SET) != 0) {
        perror(path);
        fclose(fp);
        return -1;
    }
    *length = (size_t)end;
    *data = malloc(*length == 0U ? 1U : *length);
    if (*data == NULL) {
        perror("malloc");
        fclose(fp);
        return -1;
    }
    n = fread(*data, 1U, *length, fp);
    fclose(fp);
    if (n != *length) {
        fprintf(stderr, "short read: %s\n", path);
        free(*data);
        *data = NULL;
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    const size_t count = argc > 1 ? (size_t)(argc - 1) : 0U;
    uint8_t **buffers;
    const uint8_t **messages;
    size_t *lengths;
    uint8_t (*digests)[SM3_DIGEST_SIZE];
    int status = EXIT_FAILURE;

    if (count == 0U) {
        fprintf(stderr, "usage: %s FILE...\n", argv[0]);
        return EXIT_FAILURE;
    }

    buffers = calloc(count, sizeof(*buffers));
    messages = calloc(count, sizeof(*messages));
    lengths = calloc(count, sizeof(*lengths));
    digests = calloc(count, sizeof(*digests));
    if (buffers == NULL || messages == NULL || lengths == NULL || digests == NULL) {
        perror("calloc");
        goto cleanup;
    }

    for (size_t i = 0; i < count; ++i) {
        if (read_file(argv[i + 1U], &buffers[i], &lengths[i]) != 0) {
            goto cleanup;
        }
        messages[i] = buffers[i];
    }

    if (sm3_hash_batch_auto(messages, lengths, count, digests) != 0) {
        fprintf(stderr, "SM3 batch hashing failed\n");
        goto cleanup;
    }

    for (size_t i = 0; i < count; ++i) {
        for (unsigned j = 0; j < SM3_DIGEST_SIZE; ++j) {
            printf("%02x", digests[i][j]);
        }
        putchar('\n');
    }
    status = EXIT_SUCCESS;

cleanup:
    if (buffers != NULL) {
        for (size_t i = 0; i < count; ++i) free(buffers[i]);
    }
    free(buffers);
    free(messages);
    free(lengths);
    free(digests);
    return status;
}
