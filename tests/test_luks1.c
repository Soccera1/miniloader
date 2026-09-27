/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "ml_luks1.h"

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

int main(int argc, char **argv)
{
    FILE *file, *expected_file = NULL;
    long file_size;
    uint8_t *bytes;
    uint8_t expected_sector[512], actual_sector[512];
    void *scratch;
    char passphrase[256];
    memory_disk memory;
    ml_block_device device;
    ml_luks1_volume *volume;
    const char *message = NULL;
    ml_luks1_result result;
    if (argc != 4 && argc != 5) {
        fprintf(stderr, "usage: test_luks1 IMAGE PASSPHRASE success|wrong [EXPECTED_SECTOR]\n");
        return 2;
    }
    file = fopen(argv[1], "rb");
    assert(file);
    assert(fseek(file, 0, SEEK_END) == 0);
    file_size = ftell(file);
    assert(file_size > 0 && fseek(file, 0, SEEK_SET) == 0);
    bytes = (uint8_t *)malloc((size_t)file_size);
    scratch = malloc(ML_LUKS1_SCRATCH_BYTES);
    volume = (ml_luks1_volume *)calloc(1, sizeof(*volume));
    assert(bytes && scratch && volume);
    assert(fread(bytes, 1, (size_t)file_size, file) == (size_t)file_size);
    fclose(file);
    memory.bytes = bytes;
    memory.size = (size_t)file_size;
    device.context = &memory;
    device.byte_size = memory.size;
    device.logical_block_size = 512;
    device.read_at = read_memory;
    strncpy(passphrase, argv[2], sizeof(passphrase) - 1);
    passphrase[sizeof(passphrase) - 1] = '\0';
    result = ml_luks1_open(volume, &device, passphrase, strlen(passphrase),
                           scratch, ML_LUKS1_SCRATCH_BYTES, &message);
    if (strcmp(argv[3], "success") == 0) {
        if (result != ML_LUKS1_OK) {
            fprintf(stderr, "LUKS1 unlock failed (%d): %s\n", result,
                    message ? message : "no diagnostic");
            return 1;
        }
        assert(volume->device.byte_size > 0);
        assert(volume->key_bytes == 16 || volume->key_bytes == 24 ||
               volume->key_bytes == 32 || volume->key_bytes == 64);
        if (argc == 5) {
            expected_file = fopen(argv[4], "rb");
            assert(expected_file);
            assert(fread(expected_sector, 1, sizeof(expected_sector),
                         expected_file) == sizeof(expected_sector));
            fclose(expected_file);
            assert(ml_block_read(&volume->device, 0, actual_sector,
                                 sizeof(actual_sector)) == ML_BLOCK_OK);
            assert(memcmp(actual_sector, expected_sector,
                          sizeof(actual_sector)) == 0);
        }
    } else {
        assert(result == ML_LUKS1_WRONG_PASSPHRASE);
    }
    memset(passphrase, 0, sizeof(passphrase));
    memset(expected_sector, 0, sizeof(expected_sector));
    memset(actual_sector, 0, sizeof(actual_sector));
    memset(scratch, 0, ML_LUKS1_SCRATCH_BYTES);
    memset(bytes, 0, memory.size);
    free(volume);
    free(scratch);
    free(bytes);
    puts("LUKS1 keyslot test passed");
    return 0;
}
