/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _FILE_OFFSET_BITS 64
#define _POSIX_C_SOURCE 200809L
#include "ml_extfs.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

typedef struct {
    FILE *file;
} host_disk;

static int host_read(void *context, uint64_t offset, void *buffer, size_t length)
{
    host_disk *disk = (host_disk *)context;
    if (offset > (uint64_t)INT64_MAX ||
        fseeko(disk->file, (off_t)offset, SEEK_SET) != 0)
        return -1;
    return fread(buffer, 1, length, disk->file) == length ? 0 : -1;
}

static uint64_t file_length(FILE *file)
{
    off_t at;
    assert(fseeko(file, 0, SEEK_END) == 0);
    at = ftello(file);
    assert(at >= 0);
    return (uint64_t)at;
}

static void read_and_compare(const ml_extfs_file *file, FILE *expected)
{
    uint8_t actual[8192], reference[8192];
    uint64_t offset = 0;
    assert(fseeko(expected, 0, SEEK_SET) == 0);
    while (offset < file->size) {
        size_t count = sizeof(actual), got = 0;
        if ((uint64_t)count > file->size - offset)
            count = (size_t)(file->size - offset);
        assert(ml_extfs_read(file, offset, actual, count, &got, NULL) == ML_EXTFS_OK);
        assert(got == count);
        assert(fread(reference, 1, count, expected) == count);
        assert(memcmp(actual, reference, count) == 0);
        offset += count;
    }
    assert(fgetc(expected) == EOF);
    assert(ml_extfs_read(file, file->size + 1, actual, 1, NULL, NULL) == ML_EXTFS_RANGE);
}

int main(int argc, char **argv)
{
    host_disk backing;
    ml_block_device device;
    ml_extfs filesystem;
    ml_extfs_file file;
    const char *message = NULL;
    char uuid[37];
    void *scratch;
    FILE *expected;
    uint8_t config[64];
    size_t amount = 0;

    assert(argc == 3 || argc == 4);
    backing.file = fopen(argv[1], "rb");
    expected = fopen(argv[2], "rb");
    assert(backing.file && expected);
    device.context = &backing;
    device.byte_size = file_length(backing.file);
    device.logical_block_size = 512;
    device.read_at = host_read;
    scratch = malloc(ML_EXTFS_MAX_BLOCK_SIZE);
    assert(scratch);
    if (argc == 4) {
        assert(strcmp(argv[3], "reject") == 0);
        assert(ml_extfs_mount(&filesystem, &device, scratch,
                              ML_EXTFS_MAX_BLOCK_SIZE, &message) == ML_EXTFS_UNSUPPORTED);
        assert(message && strstr(message, "unsupported"));
        fclose(expected);
        fclose(backing.file);
        free(scratch);
        puts("unsupported ext feature rejected");
        return 0;
    }
    {
        ml_extfs_result result = ml_extfs_mount(&filesystem, &device, scratch,
            ML_EXTFS_MAX_BLOCK_SIZE, &message);
        if (result != ML_EXTFS_OK) {
            fprintf(stderr, "mount failed (%d): %s\n", result,
                    message ? message : "no diagnostic");
            abort();
        }
    }
    ml_extfs_format_uuid(&filesystem, uuid);
    assert(strlen(uuid) == 36);

    assert(ml_extfs_open(&file, &filesystem, "/boot/kernel", &message) == ML_EXTFS_OK);
    read_and_compare(&file, expected);
    assert(ml_extfs_open(&file, &filesystem, "boot/../boot/kernel", &message) == ML_EXTFS_OK);
    assert(ml_extfs_open(&file, &filesystem, "/missing", &message) == ML_EXTFS_NOT_FOUND);
    assert(ml_extfs_open(&file, &filesystem, "/boot", &message) == ML_EXTFS_NOT_FILE);
    assert(ml_extfs_open(&file, &filesystem, "/boot/miniloader.conf", &message) == ML_EXTFS_OK);
    assert(ml_extfs_read(&file, 0, config, sizeof(config), &amount, &message) == ML_EXTFS_OK);
    assert(amount == 24 && memcmp(config, "timeout=5\ndefault=linux\n", amount) == 0);

    fclose(expected);
    fclose(backing.file);
    free(scratch);
    puts("read-only ext filesystem tests passed");
    return 0;
}
