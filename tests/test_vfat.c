/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "ml_vfat.h"

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
    FILE *image_file, *expected_file = NULL;
    long image_size, expected_size;
    uint8_t *image, *expected, *actual;
    size_t amount, offset = 0;
    memory_disk memory;
    ml_block_device device;
    ml_vfat filesystem;
    ml_vfat_file file;
    const char *message = NULL;
    ml_vfat_result mount_result;
    int malformed = argc == 4;
    if (argc != 3 && argc != 4) {
        fprintf(stderr, "usage: test_vfat IMAGE EXPECTED_FILE|EXPECTED_ERROR\n");
        return 2;
    }
    if (malformed && strcmp(argv[2], "check-error") != 0) return 2;
    image_file = fopen(argv[1], "rb");
    assert(image_file);
    assert(fseek(image_file, 0, SEEK_END) == 0);
    image_size = ftell(image_file);
    assert(image_size > 0 && fseek(image_file, 0, SEEK_SET) == 0);
    expected_size = 0;
    if (!malformed) {
        expected_file = fopen(argv[2], "rb");
        assert(expected_file);
        assert(fseek(expected_file, 0, SEEK_END) == 0);
        expected_size = ftell(expected_file);
        assert(expected_size >= 0 && fseek(expected_file, 0, SEEK_SET) == 0);
    }
    image = (uint8_t *)malloc((size_t)image_size);
    expected = malformed ? NULL : (uint8_t *)malloc((size_t)expected_size);
    actual = malformed ? NULL : (uint8_t *)malloc((size_t)expected_size);
    assert(image && (malformed || (expected && actual)));
    assert(fread(image, 1, (size_t)image_size, image_file) == (size_t)image_size);
    if (!malformed)
        assert(fread(expected, 1, (size_t)expected_size, expected_file) ==
               (size_t)expected_size);
    fclose(image_file);
    if (expected_file) fclose(expected_file);
    memory.bytes = image;
    memory.size = (size_t)image_size;
    device.context = &memory;
    device.byte_size = memory.size;
    device.logical_block_size = 512;
    device.read_at = read_memory;
    mount_result = ml_vfat_mount(&filesystem, &device, &message);
    if (malformed) {
        ml_vfat_result expected_result = strcmp(argv[3], "unsupported") == 0
            ? ML_VFAT_UNSUPPORTED : ML_VFAT_BAD_FORMAT;
        if (mount_result != expected_result) {
            fprintf(stderr, "VFAT malformed case expected %d, got %d: %s\n",
                    expected_result, mount_result,
                    message ? message : "no diagnostic");
            return 1;
        }
        free(image);
        return 0;
    }
    assert(mount_result == ML_VFAT_OK);
    {
        ml_vfat_result result = ml_vfat_open(&file, &filesystem,
                                              "/BOOT/miniloader.conf", &message);
        if (result != ML_VFAT_OK) {
            fprintf(stderr, "VFAT open failed (%d): %s\n", result,
                    message ? message : "no diagnostic");
            return 1;
        }
    }
    assert(file.size == (uint64_t)expected_size);
    while (offset < (size_t)expected_size) {
        size_t request = (size_t)expected_size - offset;
        if (request > 73) request = 73;
        assert(ml_vfat_read(&file, offset, actual + offset, request,
                            &amount, &message) == ML_VFAT_OK);
        assert(amount == request);
        offset += amount;
    }
    assert(memcmp(actual, expected, (size_t)expected_size) == 0);
    assert(ml_vfat_open(&file, &filesystem, "/BOOT/missing", &message) ==
           ML_VFAT_NOT_FOUND);
    free(actual);
    free(expected);
    free(image);
    puts("VFAT image read passed");
    return 0;
}
