/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef ML_XFS_H
#define ML_XFS_H

#include "ml_block.h"
#include <stddef.h>
#include <stdint.h>

typedef enum {
    ML_XFS_OK = 0,
    ML_XFS_INVALID = -1,
    ML_XFS_IO = -2,
    ML_XFS_BAD_FORMAT = -3,
    ML_XFS_UNSUPPORTED = -4,
    ML_XFS_NOT_FOUND = -5,
    ML_XFS_NOT_FILE = -6,
    ML_XFS_RANGE = -7
} ml_xfs_result;

typedef struct {
    const ml_block_device *device;
    void *state;
    char uuid[37];
    uint32_t block_size;
} ml_xfs;

typedef struct {
    const ml_xfs *filesystem;
    void *node;
    uint64_t size;
} ml_xfs_file;

ml_xfs_result ml_xfs_mount(ml_xfs *filesystem,
                           const ml_block_device *device,
                           const char **error_message);
ml_xfs_result ml_xfs_open(ml_xfs_file *file, const ml_xfs *filesystem,
                          const char *path, const char **error_message);
ml_xfs_result ml_xfs_read(const ml_xfs_file *file, uint64_t offset,
                          void *buffer, size_t length, size_t *bytes_read,
                          const char **error_message);
void ml_xfs_close_file(ml_xfs_file *file);
void ml_xfs_unmount(ml_xfs *filesystem);

#endif
