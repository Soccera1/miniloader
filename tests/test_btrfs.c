/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "ml_btrfs.h"
#include <grub/deflate.h>
#include <grub/lib/crc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char image[128 * 1024];

struct memory_image {
    const unsigned char *bytes;
    size_t size;
};

static int image_read(void *context, uint64_t offset, void *buffer, size_t length)
{
    const struct memory_image *source = context;
    if (offset > source->size || length > source->size - (size_t)offset)
        return ML_BLOCK_RANGE;
    memcpy(buffer, source->bytes + offset, length);
    return ML_BLOCK_OK;
}

static void put_le16(size_t offset, unsigned value)
{
    image[offset] = (unsigned char)value;
    image[offset + 1] = (unsigned char)(value >> 8);
}

static void put_le32(size_t offset, uint32_t value)
{
    unsigned i;
    for (i = 0; i < 4; ++i) image[offset + i] = (unsigned char)(value >> (8 * i));
}

static void put_le64(size_t offset, uint64_t value)
{
    unsigned i;
    for (i = 0; i < 8; ++i) image[offset + i] = (unsigned char)(value >> (8 * i));
}

static void set_superblock_checksum(void)
{
    put_le32(0x10000, grub_getcrc32c(0, image + 0x10020, 4096 - 0x20));
}

static int read_generated_fixture(const char *path)
{
    static const char expected_config[] = "timeout=5\ndefault=btrfs-test\n";
    FILE *input = fopen(path, "rb");
    struct memory_image source;
    ml_block_device device;
    ml_btrfs filesystem;
    ml_btrfs_file file;
    const char *message = NULL;
    unsigned char *bytes = NULL;
    unsigned char *output = NULL;
    long file_length;
    size_t amount;
    size_t i;
    int failed = 1;

    if (!input) {
        perror("could not open generated Btrfs fixture");
        return 1;
    }
    if (fseek(input, 0, SEEK_END) != 0 ||
        (file_length = ftell(input)) <= 0 ||
        fseek(input, 0, SEEK_SET) != 0) {
        fputs("could not size generated Btrfs fixture\n", stderr);
        fclose(input);
        return 1;
    }
    bytes = malloc((size_t)file_length);
    if (!bytes || fread(bytes, 1, (size_t)file_length, input) !=
                  (size_t)file_length) {
        fputs("could not read generated Btrfs fixture\n", stderr);
        goto done;
    }
    source.bytes = bytes;
    source.size = (size_t)file_length;
    device.context = &source;
    device.byte_size = source.size;
    device.logical_block_size = 512;
    device.read_at = image_read;
    ml_btrfs_set_devices(NULL, 0);

    if (ml_btrfs_mount(&filesystem, &device, &message) != ML_BTRFS_OK) {
        fprintf(stderr, "valid Btrfs fixture mount failed: %s\n",
                message ? message : "no message");
        goto done;
    }
    if (strcmp(filesystem.uuid, "4b1f3ed4-0dd0-4aac-9c8f-5a881de1724c") != 0) {
        fprintf(stderr, "Btrfs UUID decoded incorrectly: %s\n", filesystem.uuid);
        ml_btrfs_unmount(&filesystem);
        goto done;
    }
    if (ml_btrfs_open(&file, &filesystem, "/boot/miniloader.conf", &message) !=
        ML_BTRFS_OK || file.size != sizeof(expected_config) - 1) {
        fprintf(stderr, "Btrfs config path lookup failed: %s\n",
                message ? message : "no message");
        ml_btrfs_unmount(&filesystem);
        goto done;
    }
    output = malloc((size_t)file.size);
    if (!output || ml_btrfs_read(&file, 0, output, (size_t)file.size,
                                 &amount, &message) != ML_BTRFS_OK ||
        amount != (size_t)file.size ||
        memcmp(output, expected_config, sizeof(expected_config) - 1) != 0) {
        fprintf(stderr, "Btrfs config file read failed: %s\n",
                message ? message : "content mismatch");
        free(output);
        output = NULL;
        ml_btrfs_close_file(&file);
        ml_btrfs_unmount(&filesystem);
        goto done;
    }
    free(output);
    output = NULL;
    ml_btrfs_close_file(&file);

    if (ml_btrfs_open(&file, &filesystem, "/boot/payload.bin", &message) !=
        ML_BTRFS_OK || file.size != 300123) {
        fprintf(stderr, "Btrfs payload path lookup failed: %s\n",
                message ? message : "unexpected payload size");
        ml_btrfs_unmount(&filesystem);
        goto done;
    }
    output = malloc(5173);
    if (!output || ml_btrfs_read(&file, 65531, output, 5173, &amount,
                                 &message) != ML_BTRFS_OK || amount != 5173) {
        fprintf(stderr, "Btrfs extent range read failed: %s\n",
                message ? message : "short read");
        free(output);
        output = NULL;
        ml_btrfs_close_file(&file);
        ml_btrfs_unmount(&filesystem);
        goto done;
    }
    for (i = 0; i < 5173; ++i) {
        unsigned char expected = (unsigned char)((((65531 + i) * 37) ^
                                      ((65531 + i) >> 7)) & 0xff);
        if (output[i] != expected) {
            fprintf(stderr, "Btrfs payload data mismatch at %zu\n", i);
            free(output);
            output = NULL;
            ml_btrfs_close_file(&file);
            ml_btrfs_unmount(&filesystem);
            goto done;
        }
    }
    free(output);
    output = NULL;
    ml_btrfs_close_file(&file);
    ml_btrfs_unmount(&filesystem);
    failed = 0;

done:
    free(output);
    free(bytes);
    fclose(input);
    return failed;
}

int main(int argc, char **argv)
{
    static const unsigned char compressed[] = {
        0x78,0x9c,0xf3,0xcd,0xcc,0xcb,0xf4,0xc9,0x4f,0x4c,0x49,0x2d,
        0x52,0x70,0x2a,0x29,0x4a,0x2b,0x56,0xa8,0xca,0xc9,0x4c,0x52,
        0x28,0x4a,0xcc,0x4b,0x4f,0x55,0x48,0x49,0x4d,0xce,0x07,0x49,
        0xa4,0x65,0x56,0x94,0x94,0x16,0xa5,0x02,0x00,0x5d,0x17,0x10,
        0x21
    };
    static const char payload[] = "MiniLoader Btrfs zlib range decoder fixture";
    const unsigned char signature[] = "_BHRfS_M";
    const char *message = NULL;
    struct memory_image source = { image, sizeof(image) };
    ml_block_device device = { &source, sizeof(image), 512, image_read };
    ml_btrfs filesystem;
    char output[19];
    size_t got = 0;

    memset(image, 0, sizeof(image));
    if (ml_btrfs_mount(&filesystem, &device, &message) != ML_BTRFS_NOT_FOUND) {
        fputs("non-Btrfs image was not ignored\n", stderr);
        return 1;
    }

    memcpy(image + 0x10040, signature, sizeof(signature) - 1);
    if (ml_btrfs_mount(&filesystem, &device, &message) != ML_BTRFS_BAD_FORMAT) {
        fputs("malformed Btrfs superblock was not rejected\n", stderr);
        return 1;
    }

    put_le64(0x100d1, sizeof(image));
    put_le64(0x10050, 0x1000);
    put_le64(0x10058, 0x2000);
    set_superblock_checksum();
    if (ml_btrfs_mount(&filesystem, &device, &message) != ML_BTRFS_OK ||
        !filesystem.state) {
        fprintf(stderr, "valid Btrfs superblock probe failed: %s\n",
                message ? message : "no message");
        return 1;
    }
    ml_btrfs_unmount(&filesystem);

    image[0x10000] ^= 1;
    if (ml_btrfs_mount(&filesystem, &device, &message) != ML_BTRFS_BAD_FORMAT) {
        fputs("corrupt Btrfs superblock checksum was not rejected\n", stderr);
        return 1;
    }

    memset(output, 0, sizeof(output));
    if (grub_zlib_decompress((const char *)compressed, sizeof(compressed),
                             5, output, sizeof(output)) != (long)sizeof(output) ||
        memcmp(output, payload + 5, sizeof(output)) != 0) {
        fputs("Btrfs zlib range decompression failed\n", stderr);
        return 1;
    }
    if (grub_zlib_decompress("bad stream", 10, 0, output, 5) >= 0) {
        fputs("invalid zlib stream was accepted\n", stderr);
        return 1;
    }
    if (ml_btrfs_read(NULL, 0, output, sizeof(output), &got, &message) !=
        ML_BTRFS_INVALID) {
        fputs("invalid Btrfs read arguments were accepted\n", stderr);
        return 1;
    }
    if (argc != 2 || read_generated_fixture(argv[1]) != 0)
        return 1;
    puts("Btrfs superblock, path, extent, and zlib range tests passed");
    return 0;
}
