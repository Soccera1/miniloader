/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef ML_VFAT_H
#define ML_VFAT_H

#include "ml_block.h"
#include <stddef.h>
#include <stdint.h>

typedef enum {
    ML_VFAT_OK = 0,
    ML_VFAT_INVALID = -1,
    ML_VFAT_IO = -2,
    ML_VFAT_BAD_FORMAT = -3,
    ML_VFAT_UNSUPPORTED = -4,
    ML_VFAT_NOT_FOUND = -5,
    ML_VFAT_NOT_FILE = -6,
    ML_VFAT_RANGE = -7,
    ML_VFAT_NOT_VFAT = -8
} ml_vfat_result;

typedef struct {
    const ml_block_device *device;
    uint64_t fat_offset;
    uint64_t fat_size_bytes;
    uint64_t data_offset;
    uint64_t root_offset;
    uint64_t root_size;
    uint32_t cluster_count;
    uint32_t root_cluster;
    uint32_t cluster_size;
    uint16_t bytes_per_sector;
    uint8_t sectors_per_cluster;
    uint8_t fat_bits;
} ml_vfat;

typedef struct {
    const ml_vfat *filesystem;
    uint32_t first_cluster;
    uint64_t size;
    uint8_t is_directory;
} ml_vfat_file;

ml_vfat_result ml_vfat_mount(ml_vfat *filesystem,
                             const ml_block_device *device,
                             const char **error_message);
ml_vfat_result ml_vfat_open(ml_vfat_file *file, const ml_vfat *filesystem,
                            const char *path, const char **error_message);
ml_vfat_result ml_vfat_read(const ml_vfat_file *file, uint64_t offset,
                            void *buffer, size_t length, size_t *bytes_read,
                            const char **error_message);

#endif
