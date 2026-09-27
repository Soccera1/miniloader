/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef ML_ZFS_H
#define ML_ZFS_H

#include "ml_block.h"
#include <stddef.h>
#include <stdint.h>

typedef enum {
    ML_ZFS_OK = 0,
    ML_ZFS_INVALID = -1,
    ML_ZFS_IO = -2,
    ML_ZFS_BAD_FORMAT = -3,
    ML_ZFS_UNSUPPORTED = -4,
    ML_ZFS_NOT_FOUND = -5,
    ML_ZFS_NOT_FILE = -6,
    ML_ZFS_RANGE = -7
} ml_zfs_result;

typedef struct {
    const ml_block_device *device;
    void *state;
    char uuid[37];
} ml_zfs;

typedef struct {
    const ml_zfs *filesystem;
    void *handle;
    uint64_t size;
} ml_zfs_file;

void ml_zfs_set_devices(const ml_block_device *const *devices, size_t count);
ml_zfs_result ml_zfs_mount(ml_zfs *filesystem,
                           const ml_block_device *device,
                           const char **error_message);
ml_zfs_result ml_zfs_open(ml_zfs_file *file, const ml_zfs *filesystem,
                          const char *path, const char **error_message);
ml_zfs_result ml_zfs_read(const ml_zfs_file *file, uint64_t offset,
                          void *buffer, size_t length, size_t *bytes_read,
                          const char **error_message);
void ml_zfs_close_file(ml_zfs_file *file);
void ml_zfs_unmount(ml_zfs *filesystem);

#endif
