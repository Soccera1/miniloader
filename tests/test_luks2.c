/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "ml_luks2.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const uint8_t *bytes;
    size_t size;
} memory_disk;

static int read_memory(void *context, uint64_t offset,
                       void *buffer, size_t size)
{
    memory_disk *disk = (memory_disk *)context;
    if (offset > disk->size || size > disk->size - (size_t)offset) return -1;
    memcpy(buffer, disk->bytes + (size_t)offset, size);
    return 0;
}

static int allocate_argon_memory(void *context, uint8_t **memory, size_t size)
{
    (void)context;
    *memory = (uint8_t *)malloc(size);
    return *memory ? 0 : -1;
}

static void release_argon_memory(void *context, uint8_t *memory, size_t size)
{
    volatile uint8_t *p = memory;
    (void)context;
    while (size--) *p++ = 0;
    free(memory);
}

static uint8_t *read_file(const char *path, size_t *size)
{
    FILE *file = fopen(path, "rb");
    long length;
    uint8_t *bytes;
    assert(file);
    assert(fseek(file, 0, SEEK_END) == 0);
    length = ftell(file);
    assert(length > 0 && fseek(file, 0, SEEK_SET) == 0);
    bytes = (uint8_t *)malloc((size_t)length);
    assert(bytes && fread(bytes, 1, (size_t)length, file) == (size_t)length);
    fclose(file);
    *size = (size_t)length;
    return bytes;
}

int main(int argc, char **argv)
{
    size_t image_size;
    uint8_t *bytes = NULL, *expected = NULL;
    size_t expected_size = 0;
    void *scratch;
    ml_luks2_volume *volume;
    memory_disk memory;
    ml_block_device device;
    const char *message = NULL;
    ml_luks2_result result;
    int token_mode = argc == 3 && strcmp(argv[2], "token") == 0;
    if (!token_mode && argc != 4 && argc != 5) {
        fprintf(stderr, "usage: test_luks2 IMAGE PASSPHRASE success|wrong|bad|unsupported [EXPECTED], or IMAGE token\n");
        return 2;
    }
    bytes = read_file(argv[1], &image_size);
    scratch = malloc(ML_LUKS2_SCRATCH_BYTES);
    volume = (ml_luks2_volume *)calloc(1, sizeof(*volume));
    assert(scratch && volume);
    memory.bytes = bytes;
    memory.size = image_size;
    device.context = &memory;
    device.byte_size = image_size;
    device.logical_block_size = 512;
    device.read_at = read_memory;
    if (token_mode) {
        ml_tpm2_token token;
        result = ml_luks2_read_tpm2_token(&device, &token, scratch,
            ML_LUKS2_SCRATCH_BYTES, &message);
        if (result != ML_LUKS2_OK) {
            fprintf(stderr, "TPM2 token parse failed (%d): %s\n", result,
                    message ? message : "no diagnostic");
            return 1;
        }
        assert(token.pcr_mask == ((1u << 7) | (1u << 11)));
        assert(token.pcr_bank == ML_TPM2_ALG_SHA256);
        assert(token.primary_algorithm == ML_TPM2_ALG_ECC);
        assert(token.blob_size == 3 && token.blob[0] == 0 &&
               token.blob[1] == 1 && token.blob[2] == 0xaa);
        assert(token.policy_hash[0] == 0 && token.policy_hash[31] == 31);
        memset(&token, 0, sizeof(token));
        memset(scratch, 0, ML_LUKS2_SCRATCH_BYTES);
        memset(bytes, 0, image_size);
        free(volume);
        free(scratch);
        free(bytes);
        puts("systemd-compatible TPM2 token parse passed");
        return 0;
    }
    result = ml_luks2_open(volume, &device, argv[2], strlen(argv[2]),
                           scratch, ML_LUKS2_SCRATCH_BYTES,
                           allocate_argon_memory, release_argon_memory,
                           NULL, &message);
    if (strcmp(argv[3], "success") == 0) {
        if (result != ML_LUKS2_OK) {
            fprintf(stderr, "LUKS2 unlock failed (%d): %s\n", result,
                    message ? message : "no diagnostic");
            return 1;
        }
        assert(volume->sector_size == 4096 || volume->sector_size == 512);
        assert(volume->key_bytes == 32 || volume->key_bytes == 64);
        assert(volume->device.byte_size > 0);
        if (argc == 5) {
            uint8_t *actual;
            expected = read_file(argv[4], &expected_size);
            assert(expected_size <= volume->device.byte_size);
            actual = (uint8_t *)malloc(expected_size);
            assert(actual);
            assert(ml_block_read(&volume->device, 0, actual,
                                 expected_size) == ML_BLOCK_OK);
            assert(memcmp(actual, expected, expected_size) == 0);
            memset(actual, 0, expected_size);
            free(actual);
        }
    } else if (strcmp(argv[3], "wrong") == 0) {
        assert(result == ML_LUKS2_WRONG_PASSPHRASE);
    } else if (strcmp(argv[3], "bad") == 0) {
        assert(result == ML_LUKS2_BAD_FORMAT);
    } else {
        assert(result == ML_LUKS2_UNSUPPORTED);
    }
    if (expected) {
        memset(expected, 0, expected_size);
        free(expected);
    }
    memset(argv[2], 0, strlen(argv[2]));
    memset(scratch, 0, ML_LUKS2_SCRATCH_BYTES);
    memset(bytes, 0, image_size);
    free(volume);
    free(scratch);
    free(bytes);
    puts("LUKS2 keyslot test passed");
    return 0;
}
