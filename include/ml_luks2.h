/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef ML_LUKS2_H
#define ML_LUKS2_H

#include "ml_block.h"
#include "ml_argon2id.h"
#include "ml_crypto.h"
#include "ml_tpm2.h"
#include <stddef.h>
#include <stdint.h>

#define ML_LUKS2_METADATA_MAX_BYTES (64u * 1024u)
#define ML_LUKS2_MAX_AF_BYTES (64u * 4000u)
#define ML_LUKS2_MAX_AREA_BYTES (64u * 4096u)
#define ML_LUKS2_SCRATCH_BYTES \
    (2u * ML_LUKS2_METADATA_MAX_BYTES + ML_LUKS2_MAX_AREA_BYTES)
#define ML_LUKS2_MAX_KEY_BYTES 64u

typedef enum {
    ML_LUKS2_OK = 0,
    ML_LUKS2_NOT_LUKS = 1,
    ML_LUKS2_WRONG_PASSPHRASE = -1,
    ML_LUKS2_BAD_FORMAT = -2,
    ML_LUKS2_UNSUPPORTED = -3,
    ML_LUKS2_IO = -4,
    ML_LUKS2_RANGE = -5,
    ML_LUKS2_INVALID = -6
} ml_luks2_result;

typedef struct {
    const ml_block_device *parent;
    uint64_t payload_offset;
    uint64_t byte_size;
    uint64_t iv_tweak;
    uint32_t sector_size;
    uint32_t key_bytes;
    ml_xts_cipher cipher;
    uint8_t aes_cbc_essiv;
    uint8_t master_key[ML_LUKS2_MAX_KEY_BYTES];
    uint8_t sector_buffer[4096];
    ml_block_device device;
} ml_luks2_volume;

ml_luks2_result ml_luks2_open(ml_luks2_volume *volume,
                              const ml_block_device *device,
                              const void *passphrase, size_t passphrase_size,
                              void *scratch, size_t scratch_size,
                              ml_argon2_allocate_fn argon_allocate,
                              ml_argon2_free_fn argon_release,
                              void *argon_allocator_context,
                              const char **error_message);

/* Reads a systemd-compatible TPM2 token from authenticated LUKS2 metadata. */
ml_luks2_result ml_luks2_read_tpm2_token(const ml_block_device *device,
                                         ml_tpm2_token *token,
                                         void *scratch, size_t scratch_size,
                                         const char **error_message);

#endif
