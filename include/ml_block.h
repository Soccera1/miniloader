/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef ML_BLOCK_H
#define ML_BLOCK_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    ML_BLOCK_OK = 0,
    ML_BLOCK_INVALID = -1,
    ML_BLOCK_RANGE = -2,
    ML_BLOCK_IO = -3,
    ML_BLOCK_NOT_FOUND = -4,
    ML_BLOCK_BAD_FORMAT = -5,
    ML_BLOCK_AMBIGUOUS = -6
} ml_block_result;

typedef int (*ml_block_read_fn)(void *context, uint64_t offset,
                                void *buffer, size_t length);

/* Read-only byte-addressable device. Layer implementations can wrap another
 * device as their context and translate reads without exposing writes. */
typedef struct {
    void *context;
    uint64_t byte_size;
    uint32_t logical_block_size;
    ml_block_read_fn read_at;
} ml_block_device;

typedef struct {
    ml_block_device device;
    const ml_block_device *parent;
    uint64_t base_offset;
} ml_block_slice;

typedef struct {
    uint8_t partition_guid[16]; /* Raw GPT on-disk byte order. */
    uint64_t first_lba;
    uint64_t last_lba;
} ml_gpt_partition;

int ml_block_read(const ml_block_device *device, uint64_t offset,
                  void *buffer, size_t length);
int ml_block_slice_init(ml_block_slice *slice, const ml_block_device *parent,
                        uint64_t first_lba, uint64_t block_count);
int ml_gpt_find_partition(const ml_block_device *disk,
                           const uint8_t partition_guid[16],
                           void *scratch, size_t scratch_size,
                           ml_gpt_partition *partition);

#endif
