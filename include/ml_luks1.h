/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef ML_LUKS1_H
#define ML_LUKS1_H

#include "ml_block.h"
#include <stddef.h>
#include <stdint.h>

#define ML_LUKS1_MAX_KEY_BYTES 64u
#define ML_LUKS1_MAX_STRIPES 4000u
#define ML_LUKS1_SCRATCH_BYTES \
    (ML_LUKS1_MAX_KEY_BYTES * ML_LUKS1_MAX_STRIPES)

typedef enum {
    ML_LUKS1_OK = 0,
    ML_LUKS1_NOT_LUKS = 1,
    ML_LUKS1_WRONG_PASSPHRASE = -1,
    ML_LUKS1_BAD_FORMAT = -2,
    ML_LUKS1_UNSUPPORTED = -3,
    ML_LUKS1_IO = -4,
    ML_LUKS1_RANGE = -5,
    ML_LUKS1_INVALID = -6
} ml_luks1_result;

typedef struct {
    const ml_block_device *parent;
    uint64_t payload_offset;
    uint64_t byte_size;
    uint8_t cipher_profile; /* 0 AES-XTS, 1 AES-CBC-ESSIV, 2 Serpent-XTS, 3 Twofish-XTS. */
    uint32_t key_bytes;
    uint8_t master_key[ML_LUKS1_MAX_KEY_BYTES];
    uint8_t sector_buffer[512];
    ml_block_device device;
} ml_luks1_volume;

ml_luks1_result ml_luks1_open(ml_luks1_volume *volume,
                              const ml_block_device *device,
                              const void *passphrase, size_t passphrase_size,
                              void *scratch, size_t scratch_size,
                              const char **error_message);

#endif
