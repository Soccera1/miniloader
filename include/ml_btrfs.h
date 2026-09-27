/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef ML_BTRFS_H
#define ML_BTRFS_H

#include "ml_block.h"
#include <stddef.h>
#include <stdint.h>

typedef enum {
    ML_BTRFS_OK = 0,
    ML_BTRFS_INVALID = -1,
    ML_BTRFS_IO = -2,
    ML_BTRFS_BAD_FORMAT = -3,
    ML_BTRFS_UNSUPPORTED = -4,
    ML_BTRFS_NOT_FOUND = -5,
    ML_BTRFS_NOT_FILE = -6,
    ML_BTRFS_RANGE = -7
} ml_btrfs_result;

typedef struct {
    const ml_block_device *device;
    void *state;
    char uuid[37];
} ml_btrfs;

typedef struct {
    const ml_btrfs *filesystem;
    void *handle;
    uint64_t size;
} ml_btrfs_file;

/* Registry is used only for locating members of multi-device Btrfs volumes. */
void ml_btrfs_set_devices(const ml_block_device *const *devices, size_t count);
ml_btrfs_result ml_btrfs_mount(ml_btrfs *filesystem,
                               const ml_block_device *device,
                               const char **error_message);
ml_btrfs_result ml_btrfs_open(ml_btrfs_file *file,
                              const ml_btrfs *filesystem,
                              const char *path,
                              const char **error_message);
ml_btrfs_result ml_btrfs_read(const ml_btrfs_file *file, uint64_t offset,
                              void *buffer, size_t length,
                              size_t *bytes_read,
                              const char **error_message);
void ml_btrfs_close_file(ml_btrfs_file *file);
void ml_btrfs_unmount(ml_btrfs *filesystem);

#endif
