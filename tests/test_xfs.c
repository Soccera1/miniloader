/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "ml_xfs.h"
#include <limits.h>
#include <stdio.h>
#include <string.h>

typedef struct { FILE *file; uint64_t size; int corrupt_incompat; } test_disk;

static int read_at(void *context, uint64_t offset, void *buffer, size_t length)
{
    test_disk *disk = (test_disk *)context;
    if (offset > disk->size || length > disk->size - offset ||
        offset > (uint64_t)LONG_MAX || fseek(disk->file, (long)offset, SEEK_SET))
        return -1;
    if (fread(buffer, 1, length, disk->file) != length) return -1;
    /* XFS superblock sb_features_incompat is at byte offset 216. */
    if (disk->corrupt_incompat && offset == 0 && length >= 220)
        ((unsigned char *)buffer)[216] = 0x80;
    return 0;
}

int main(int argc, char **argv)
{
    static const char expected[] = "MiniLoader XFS fixture\n";
    test_disk backing;
    ml_block_device device;
    ml_xfs filesystem;
    ml_xfs_file file;
    const char *message = NULL;
    char output[128];
    size_t got = 0;
    if (argc != 2) return 2;
    backing.file = fopen(argv[1], "rb");
    if (!backing.file) { perror("fopen"); return 2; }
    if (fseek(backing.file, 0, SEEK_END)) return 2;
    backing.size = (uint64_t)ftell(backing.file);
    backing.corrupt_incompat = 0;
    device.context = &backing;
    device.byte_size = backing.size;
    device.logical_block_size = 512;
    device.read_at = read_at;
    if (ml_xfs_mount(&filesystem, &device, &message) != ML_XFS_OK) {
        fprintf(stderr, "XFS mount failed: %s\n", message ? message : "unknown error");
        return 1;
    }
    if (strlen(filesystem.uuid) != 36 || filesystem.block_size < 512) return 1;
    if (ml_xfs_open(&file, &filesystem, "/boot/hello.txt", &message) != ML_XFS_OK) {
        fprintf(stderr, "XFS open failed: %s\n", message ? message : "unknown error");
        ml_xfs_unmount(&filesystem);
        return 1;
    }
    if (file.size != sizeof(expected) - 1 ||
        ml_xfs_read(&file, 0, output, sizeof(output), &got, &message) != ML_XFS_OK ||
        got != sizeof(expected) - 1 || memcmp(output, expected, got) != 0) {
        fprintf(stderr, "XFS payload read failed: %s\n", message ? message : "size/content mismatch");
        ml_xfs_close_file(&file);
        ml_xfs_unmount(&filesystem);
        return 1;
    }
    ml_xfs_close_file(&file);
    if (ml_xfs_open(&file, &filesystem, "/boot/hello-link", &message) != ML_XFS_OK ||
        ml_xfs_read(&file, 0, output, sizeof(output), &got, &message) != ML_XFS_OK ||
        got != sizeof(expected) - 1 || memcmp(output, expected, got) != 0) {
        fprintf(stderr, "XFS symlink read failed: %s\n", message ? message : "size/content mismatch");
        ml_xfs_close_file(&file);
        ml_xfs_unmount(&filesystem);
        return 1;
    }
    ml_xfs_close_file(&file);
    if (ml_xfs_open(&file, &filesystem, "/boot/missing", &message) != ML_XFS_NOT_FOUND) {
        fprintf(stderr, "XFS missing-file lookup did not fail as expected\n");
        ml_xfs_unmount(&filesystem);
        return 1;
    }
    ml_xfs_unmount(&filesystem);
    backing.corrupt_incompat = 1;
    if (ml_xfs_mount(&filesystem, &device, &message) != ML_XFS_UNSUPPORTED) {
        fprintf(stderr, "XFS unsupported incompatibility flag was not rejected\n");
        if (filesystem.state) ml_xfs_unmount(&filesystem);
        return 1;
    }
    fclose(backing.file);
    puts("XFS fixture read passed");
    return 0;
}
