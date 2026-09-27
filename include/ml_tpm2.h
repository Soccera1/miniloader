/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef ML_TPM2_H
#define ML_TPM2_H

#include <stddef.h>
#include <stdint.h>

#define ML_TPM2_MAX_COMMAND_BYTES 4096u
#define ML_TPM2_MAX_RESPONSE_BYTES 4096u
#define ML_TPM2_ALG_SHA1 0x0004u
#define ML_TPM2_ALG_SHA256 0x000bu
#define ML_TPM2_ALG_ECC 0x0023u
#define ML_TPM2_ALG_RSA 0x0001u

typedef int (*ml_tpm2_submit_fn)(void *context,
                                 const uint8_t *command, size_t command_size,
                                 uint8_t *response, size_t response_capacity,
                                 size_t *response_size);

typedef struct {
    uint32_t pcr_mask;
    uint16_t pcr_bank;
    uint16_t primary_algorithm;
    uint8_t policy_hash[32];
    uint8_t blob[3072];
    size_t blob_size;
} ml_tpm2_token;

/* Returns zero on success and wipes output on every error path. */
int ml_tpm2_unseal(ml_tpm2_submit_fn submit, void *context,
                   const ml_tpm2_token *token,
                   uint8_t *secret, size_t secret_capacity,
                   size_t *secret_size);

#endif
