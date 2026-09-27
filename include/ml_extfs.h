/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef ML_EXTFS_H
#define ML_EXTFS_H

#include "ml_block.h"
#include <stddef.h>
#include <stdint.h>

#define ML_EXTFS_UUID_BYTES 16u
#define ML_EXTFS_INODE_BYTES 128u
#define ML_EXTFS_MAX_BLOCK_SIZE 65536u

typedef enum {
    ML_EXTFS_OK = 0,
    ML_EXTFS_INVALID = -1,
    ML_EXTFS_IO = -2,
    ML_EXTFS_BAD_FORMAT = -3,
    ML_EXTFS_UNSUPPORTED = -4,
    ML_EXTFS_NOT_FOUND = -5,
    ML_EXTFS_NOT_FILE = -6,
    ML_EXTFS_RANGE = -7
} ml_extfs_result;

/* This is a read-only filesystem handle. The caller owns scratch and must
 * provide at least block_size bytes after mount returns successfully. */
typedef struct {
    const ml_block_device *device;
    uint8_t *scratch;
    size_t scratch_size;
    uint8_t uuid[ML_EXTFS_UUID_BYTES];
    uint64_t blocks_count;
    uint64_t inodes_count;
    uint64_t blocks_per_group;
    uint64_t inodes_per_group;
    uint32_t block_size;
    uint32_t inode_size;
    uint32_t descriptor_size;
    uint32_t first_data_block;
    uint32_t incompat_features;
    uint32_t compat_features;
    uint32_t ro_compat_features;
} ml_extfs;

typedef struct {
    const ml_extfs *filesystem;
    uint64_t inode_number;
    uint64_t size;
    uint8_t inode[ML_EXTFS_INODE_BYTES];
} ml_extfs_file;

/* Probe the superblock and mount a volume. 'scratch' is supplied by the
 * caller; mount reports the needed block_size even when it is too small. */
ml_extfs_result ml_extfs_mount(ml_extfs *filesystem,
                               const ml_block_device *device,
                               void *scratch, size_t scratch_size,
                               const char **error_message);
ml_extfs_result ml_extfs_open(ml_extfs_file *file, const ml_extfs *filesystem,
                              const char *path, const char **error_message);
ml_extfs_result ml_extfs_read(const ml_extfs_file *file, uint64_t offset,
                              void *buffer, size_t length, size_t *bytes_read,
                              const char **error_message);
void ml_extfs_format_uuid(const ml_extfs *filesystem, char output[37]);

#endif
